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
//!
//! The strip WRAPS onto as many rows as the tabs need, and the content pane starts below whatever
//! that came to. A tab that exists must be clickable at every width, so the one thing the strip may
//! never do is leave a chip out — an undrawn tab is not a degraded tab, it is a missing feature with
//! no route to it (dig_ecosystem#2309, where a seventh tab took `Settings` out of reach).

use egui::{Rect, Sense, Ui, Vec2};

use super::super::paint;
use super::super::render::{radius, regular, rgba, semibold, size, space};
use super::super::theme::Tokens;
use super::pane::{self, facts::PaneFacts};
use crate::tray_menu::TrayAction;
use crate::window_model::{tab_element_id, Tab, TabId, WindowModel};

/// How wide the sidebar is when there is room for one.
const SIDEBAR_WIDTH: f32 = 208.0;
/// Below this window width the sidebar becomes a strip of chips across the top.
///
/// Chosen from the layout rather than by taste: the sidebar plus two content gutters plus a readable
/// content column is about this wide, and under it the content column is the thing that loses.
const NARROW_AT: f32 = 760.0;
/// The height of a single-row tab strip in narrow mode.
const STRIP_HEIGHT: f32 = 44.0;
/// The gap between chip rows once the strip needs more than one.
const STRIP_ROW_GAP: f32 = 4.0;
/// A sidebar entry's height.
const TAB_HEIGHT: f32 = 36.0;

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
#[allow(clippy::too_many_arguments)]
pub(super) fn draw(
    ui: &mut Ui,
    body: Rect,
    t: &Tokens,
    model: &WindowModel,
    facts: &PaneFacts,
    selected: TabId,
    live: bool,
) -> Option<Click> {
    if model.tabs.is_empty() {
        // Unreachable from `window_model::build`, which always emits at least the Status tab, and
        // handled anyway: an empty window that painted nothing would be a blank rectangle with no
        // explanation, which is the one thing a window must never be.
        return no_tabs(ui, body, t);
    }

    // The strip is laid out BEFORE the split because its height is a result of that layout, not an
    // input to it: how many rows the chips need is what decides where the content pane starts.
    let narrow = body.width() < NARROW_AT;
    let plan = narrow.then(|| strip_layout(ui, body, &model.tabs));
    let (nav, content, status) = split(body, plan.as_ref().map(|plan| plan.height));
    let clicked = match plan {
        Some(plan) => strip(ui, nav, t, model, selected, live, &plan),
        None => sidebar(ui, nav, t, model, selected, live, facts),
    };
    // In narrow mode there is no sidebar to sit under, so the readings run along the BOTTOM of the
    // window instead — still out of the reading path, still on every tab, and still never above the
    // content (dig_ecosystem#3007).
    if let Some(status) = status {
        super::header::strip(ui, status, t, facts);
    }
    let tab = model.tab(selected).or_else(|| model.tabs.first());
    let in_content = tab.and_then(|tab| pane(ui, content, t, tab, facts, live));
    clicked.or(in_content)
}

/// Where the navigation goes, where the content goes, and where the status readings go.
///
/// `strip` is the height the wrapped tab strip came to, or `None` when there is room for a sidebar.
///
/// The third rectangle is `Some` only in narrow mode: with a sidebar the readings live inside the
/// navigation column and need no band of their own, and without one they take a band along the
/// bottom of the window (dig_ecosystem#3007). Either way the content pane is what is LEFT, so a
/// readout can never be painted across a pane that still believes it owns the full rectangle.
fn split(body: Rect, strip: Option<f32>) -> (Rect, Rect, Option<Rect>) {
    let Some(height) = strip else {
        return (
            Rect::from_min_size(body.left_top(), Vec2::new(SIDEBAR_WIDTH, body.height())),
            Rect::from_min_max(
                egui::Pos2::new(body.left() + SIDEBAR_WIDTH, body.top()),
                body.right_bottom(),
            ),
            None,
        );
    };
    // Clamped, so a window too short to hold both the tab strip and the status band gives the band
    // whatever is left rather than a negative content pane. The tabs win that contest: a tab is a
    // route to a feature and a reading is a glance.
    let status_top = (body.bottom() - super::header::HEADER_HEIGHT).max(body.top() + height);
    (
        Rect::from_min_size(body.left_top(), Vec2::new(body.width(), height)),
        Rect::from_min_max(
            egui::Pos2::new(body.left(), body.top() + height),
            egui::Pos2::new(body.right(), status_top),
        ),
        Some(Rect::from_min_max(
            egui::Pos2::new(body.left(), status_top),
            body.right_bottom(),
        )),
    )
}

/// The vertical sidebar: the tabs at the top, the status readings at the foot.
fn sidebar(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    model: &WindowModel,
    selected: TabId,
    live: bool,
    facts: &PaneFacts,
) -> Option<Click> {
    ui.painter().rect_filled(at, 0, rgba(t.surface));
    ui.painter().vline(
        at.right(),
        at.top()..=at.bottom(),
        egui::Stroke::new(1.0_f32, rgba(t.border)),
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

    // The readings take everything below the last tab and sit at the BOTTOM of it
    // (dig_ecosystem#3007). Handed the whole remainder rather than a reserved band, so the column
    // knows its true room and can say honestly whether a reading fits.
    super::header::column(
        ui,
        Rect::from_min_max(egui::Pos2::new(at.left(), y + space::S3), at.right_bottom()),
        t,
        facts,
    );
    clicked
}

/// Where every chip goes, and how tall the strip that holds them came out.
struct StripLayout {
    /// Each tab's chip, in the model's tab order, so the caller can pair them up without searching.
    chips: Vec<Rect>,
    /// The height the strip needs for the rows it used.
    height: f32,
}

/// The padding above the first chip row and below the last, so one row is exactly [`STRIP_HEIGHT`].
const STRIP_PAD: f32 = (STRIP_HEIGHT - TAB_HEIGHT) / 2.0;

/// How tall a strip of `rows` rows of chips is.
fn strip_height(rows: usize) -> f32 {
    let gaps = rows.saturating_sub(1) as f32 * STRIP_ROW_GAP;
    rows as f32 * TAB_HEIGHT + gaps + STRIP_PAD * 2.0
}

/// Lay the chips out left to right, wrapping onto a new row whenever the next one will not fit.
///
/// # Why wrapping, and not scrolling or an overflow menu
///
/// A tab strip's whole promise is that the choices are visible at a glance. A horizontal scroller
/// keeps that promise only for whoever notices the scrollbar, and a 44 px strip has nowhere to put
/// an affordance that says so — nor should the window ask for a second scroll axis when the content
/// pane already owns one. An overflow menu costs an extra click and a second mental model for the
/// same six words. Wrapping costs one more row of a window with vertical room to spare, and hides,
/// nests and gestures for nothing.
///
/// The row count is deliberately unbounded: a strip tall enough to look silly is still a strip
/// every tab can be clicked in, and capping it would put us back where dig_ecosystem#2309 started.
fn strip_layout(ui: &Ui, at: Rect, tabs: &[Tab]) -> StripLayout {
    let usable = (at.width() - space::S2 * 2.0).max(1.0);
    let mut chips = Vec::with_capacity(tabs.len());
    let (mut x, mut row) = (0.0_f32, 0_usize);
    for tab in tabs {
        // Clamped to the row: a label wider than the whole window — a translation, or a name nobody
        // has written yet — is drawn truncated by `tab_entry` rather than made unclickable.
        let width = chip_width(ui, &tab.label).min(usable);
        if x > 0.0 && x + width > usable {
            row += 1;
            x = 0.0;
        }
        let top = at.top() + STRIP_PAD + row as f32 * (TAB_HEIGHT + STRIP_ROW_GAP);
        chips.push(Rect::from_min_size(
            egui::Pos2::new(at.left() + space::S2 + x, top),
            Vec2::new(width, TAB_HEIGHT),
        ));
        x += width + space::S2 / 2.0;
    }
    StripLayout {
        chips,
        height: strip_height(row + 1),
    }
}

/// The horizontal tab strip used when the window is too narrow for a sidebar.
fn strip(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    model: &WindowModel,
    selected: TabId,
    live: bool,
    plan: &StripLayout,
) -> Option<Click> {
    ui.painter().rect_filled(at, 0, rgba(t.surface));
    paint::rule(ui, at, at.bottom(), t);

    let mut clicked = None;
    for (tab, entry) in model.tabs.iter().zip(&plan.chips) {
        if tab_entry(ui, *entry, t, tab, tab.id == selected, live) {
            clicked = Some(Click::Tab(tab.id));
        }
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

/// A single line of `label`, cut short with an ellipsis when it is wider than `max_width`.
fn truncated(
    ui: &Ui,
    label: &str,
    font: egui::FontId,
    colour: egui::Color32,
    max_width: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut job = egui::text::LayoutJob::single_section(
        label.to_owned(),
        egui::TextFormat {
            font_id: font,
            color: colour,
            ..Default::default()
        },
    );
    job.wrap = egui::text::TextWrapping {
        max_width: max_width.max(0.0),
        max_rows: 1,
        break_anywhere: true,
        overflow_character: Some('\u{2026}'),
    };
    ui.fonts(|fonts| fonts.layout_job(job))
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
    // Truncated to its own entry rather than allowed to run past it: a chip narrowed to fit the
    // window must still read as one control, and a word spilling over the next chip reads as damage.
    let galley = truncated(ui, &tab.label, font, rgba(colour), at.width() - space::S4);
    ui.painter().galley(
        egui::Pos2::new(at.left() + space::S3, at.center().y - galley.size().y / 2.0),
        galley,
        egui::Color32::PLACEHOLDER,
    );
    response.clicked()
}

/// The selected tab's content, inside a scroll area.
///
/// # Why this scrolls
///
/// It used to clamp: sections were drawn until the cursor passed the bottom of the pane and the rest
/// were silently dropped, while `Tab::actions()` went on enumerating them as offered. At 480x480
/// that already put `Remove this account from this computer...` out of reach on the Account tab
/// (dig_ecosystem#2327) - the same class of defect as dig_ecosystem#2309, one level down: there a
/// TAB vanished, here a control inside a tab did.
///
/// Every richer pane is taller than the row list it replaced, so the clamp had to go before the
/// vocabulary landed rather than after. A verb the model offers is now reachable at every size the
/// window can be dragged to, by scrolling to it.
fn pane(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    tab: &Tab,
    facts: &PaneFacts,
    live: bool,
) -> Option<Click> {
    let inner_width = at.width() - space::S5 * 2.0;
    if inner_width <= 0.0 || at.height() <= 0.0 {
        return None;
    }

    let mut clicked = None;
    // `scope_builder`, never `new_child`: a child made with `new_child` does not advance its parent,
    // so the enclosing `Area`'s interact rect never grows to cover the pane — and a scroll area the
    // pointer is never considered to be OVER silently ignores every wheel event. The content still
    // draws, which is what makes it so easy to miss: the pane looked right and simply could not be
    // scrolled, leaving the verbs below the fold unreachable.
    ui.scope_builder(egui::UiBuilder::new().max_rect(at), |ui| {
        egui::ScrollArea::vertical()
            .id_salt(("dig-window-pane", tab_element_id(tab.id)))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // The pane paints into absolute rectangles, so the column is taken from the scroll
                // area's own cursor and given unbounded height; the space actually used is allocated
                // afterwards, which is what tells the scroll area how far it may scroll. Anything below
                // the viewport is culled by the scroll area's clip rect - including for hit testing, so
                // a control that is scrolled out of view is not clickable rather than invisibly live.
                let top_left = ui.cursor().left_top() + Vec2::splat(space::S5);
                let column = Rect::from_min_size(top_left, Vec2::new(inner_width, f32::INFINITY));
                let (used, pressed) = pane::draw_tab(ui, column, t, tab, facts, live);
                clicked = pressed.map(Click::Act);
                // Allocate up to where the content ACTUALLY ends, not a fresh block of its whole
                // height (dig_ecosystem#3009).
                //
                // Some blocks draw through widgets that allocate — `paint::button` measures itself
                // through egui's layout — so by the time the pane is laid out the scroll area's
                // cursor has already advanced past part of the content. Allocating `used` on top of
                // that counted the same pixels twice, and the surplus was pure blank: the Home tab
                // at 480 px could be dragged 1,863 px past its last row, a screenful of nothing
                // with no cue that the content had ended.
                //
                // Recomputed from THIS frame's measurement every frame, which is what makes it
                // correct across a pane that changes height mid-scroll — a loading state resolving,
                // the transaction sheet opening. The extent follows the content in the same frame
                // the content changes, and egui clamps a now-too-large offset itself, so a pane
                // that shrinks under a person pulls the view back to its new end rather than
                // stranding them below it.
                let ends_at = column.top() + used + space::S5;
                ui.allocate_space(Vec2::new(
                    at.width(),
                    (ends_at - ui.cursor().top()).max(0.0),
                ));
            });
    });
    clicked
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tray_menu::{MenuRow, TrayView};
    use crate::window_model::{PaneNote, Section};
    use std::cell::Cell;

    /// A body drawn by the real [`draw`], frame by frame, so a test can click what it drew.
    ///
    /// Deliberately the same entry point the shell calls rather than [`strip`] directly: a strip
    /// that lays chips out perfectly is worth nothing if the body never reaches it, and a test that
    /// called the layout helper itself could not tell the two apart.
    struct Body {
        ctx: egui::Context,
        model: WindowModel,
        facts: PaneFacts,
        selected: TabId,
        size: Vec2,
        /// What the last frame painted, for the assertions that read text rather than controls.
        painted: egui::FullOutput,
        /// Where the content pane actually was last frame.
        ///
        /// Taken from the production [`split`], inside the production frame, so a test can never
        /// assert reachability against a rectangle the window does not use. Before the status
        /// readings took a band along the bottom in narrow mode (dig_ecosystem#3007), "the content
        /// pane" and "the window" were the same rectangle and every test said the latter; a probe
        /// point 20 px off the bottom edge silently stopped landing on the scroll area.
        content: Rect,
    }

    impl Body {
        fn holding(tabs: Vec<Tab>, width: f32) -> Self {
            let ctx = egui::Context::default();
            super::super::install_fonts(&ctx);
            let selected = tabs.first().expect("a tab").id;
            let body = Self {
                ctx,
                model: WindowModel { tabs },
                facts: PaneFacts::of_tray(&TrayView::default()),
                selected,
                size: Vec2::new(width, super::super::shell::SHELL_MIN),
                painted: egui::FullOutput::default(),
                content: Rect::NOTHING,
            };
            body.settled()
        }

        /// Two quiet frames: the first builds the font atlas, the second lays out against it.
        fn settled(mut self) -> Self {
            self.frame(Vec::new());
            self.frame(Vec::new());
            self
        }

        fn frame(&mut self, events: Vec<egui::Event>) -> Option<Click> {
            let screen = Rect::from_min_size(egui::Pos2::ZERO, self.size);
            let input = egui::RawInput {
                screen_rect: Some(screen),
                events,
                ..Default::default()
            };
            let tokens = crate::confirm::gui::theme::Theme::Light.tokens();
            let clicked = Cell::new(None);
            let content = Cell::new(Rect::NOTHING);
            let (model, facts, selected) = (&self.model, &self.facts, self.selected);
            self.painted = self.ctx.run(input, |ctx| {
                egui::Area::new(egui::Id::new("dig-app-test-body"))
                    .fixed_pos(screen.left_top())
                    .order(egui::Order::Background)
                    .show(ctx, |ui| {
                        ui.set_clip_rect(screen);
                        let plan = (screen.width() < NARROW_AT)
                            .then(|| strip_layout(ui, screen, &model.tabs));
                        content.set(split(screen, plan.map(|plan| plan.height)).1);
                        clicked.set(draw(ui, screen, &tokens, model, facts, selected, true));
                    });
            });
            self.content = content.get();
            clicked.get()
        }

        /// Scroll the pane by `delta` logical pixels (negative scrolls DOWN the content).
        fn scroll(&mut self, over: egui::Pos2, delta: f32) {
            self.frame(vec![
                egui::Event::PointerMoved(over),
                egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point,
                    delta: Vec2::new(0.0, delta),
                    modifiers: egui::Modifiers::default(),
                },
            ]);
        }

        /// Scroll `element` fully into `viewport`, the way a person would, and report where it
        /// came to rest.
        ///
        /// # Why every read is taken from a SETTLED frame
        ///
        /// egui eases a scroll over several frames, and the easing takes a frame or two to start —
        /// so a mid-animation frame is both the wrong place to read a rectangle and
        /// indistinguishable from a settled one. Reading during the animation is what made this
        /// harness see the log-folder button at y=198 and then press at y=734.
        fn scroll_into_view(
            &mut self,
            element: egui::Id,
            probe: egui::Pos2,
            viewport: Rect,
        ) -> Option<Rect> {
            // Far more than any pane is tall, so the search always begins from the top.
            self.scroll(probe, 10_000.0);
            let mut rect = self.resting_place(element);
            for _ in 0..60 {
                if rect.is_some_and(|rect| viewport.contains_rect(rect)) {
                    return rect;
                }
                self.scroll(probe, -SCROLL_STEP);
                rect = self.resting_place(element);
            }
            rect.filter(|rect| viewport.contains_rect(*rect))
        }

        /// Run quiet frames until `element` has held still for [`STILL_FRAMES`], and report where
        /// it is.
        fn resting_place(&mut self, element: egui::Id) -> Option<Rect> {
            let mut last = self.control(element);
            let mut still = 0;
            for _ in 0..300 {
                self.frame(Vec::new());
                let now = self.control(element);
                still = match (last, now) {
                    (Some(last), Some(now)) if (now.top() - last.top()).abs() < 0.01 => still + 1,
                    _ => 0,
                };
                last = now;
                if still >= STILL_FRAMES {
                    break;
                }
            }
            last
        }

        /// Scroll the pane back to the very top.
        fn scroll_to_the_top(&mut self, probe: egui::Pos2) {
            self.scroll(probe, 10_000.0);
            for _ in 0..STILL_FRAMES {
                self.frame(Vec::new());
            }
        }

        /// Scroll the pane as far down as it will go.
        fn scroll_to_the_end(&mut self, probe: egui::Pos2) {
            for _ in 0..40 {
                self.scroll(probe, -SCROLL_STEP * 4.0);
            }
            for _ in 0..STILL_FRAMES {
                self.frame(Vec::new());
            }
        }

        /// The lowest edge of anything the pane actually DREW inside the content region.
        ///
        /// Ink, not controls: a pane's last element is frequently a card, a sentence or a meter
        /// rather than a clickable row, so measuring the last ROW would report a pane as
        /// overscrolled while the person is looking at its final paragraph. Restricted to the
        /// content region so the sidebar's own ink — tabs and status readings, which do not scroll
        /// — cannot answer for the pane.
        fn lowest_ink(&mut self) -> Option<f32> {
            fn walk(shape: &egui::Shape, within: Rect, lowest: &mut Option<f32>) {
                if let egui::Shape::Vec(shapes) = shape {
                    shapes.iter().for_each(|s| walk(s, within, lowest));
                    return;
                }
                let egui::Shape::Text(_) = shape else {
                    return;
                };
                let at = shape.visual_bounding_rect();
                // Strictly inside, not merely touching: the status band starts exactly where the
                // content pane ends, so a test that accepted an intersection would measure the
                // BAND's ink as the pane's and report every pane as perfectly full. Same for the
                // sidebar on the left edge.
                let inside = at.is_finite()
                    && at.top() < within.bottom() - 0.5
                    && at.bottom() > within.top() + 0.5
                    && at.left() > within.left() - 0.5;
                if !inside {
                    return;
                }
                let bottom = at.bottom().min(within.bottom());
                *lowest = Some(lowest.map_or(bottom, |seen: f32| seen.max(bottom)));
            }
            self.frame(Vec::new());
            let within = self.content;
            let mut lowest = None;
            for clipped in &self.painted.shapes {
                walk(&clipped.shape, within, &mut lowest);
            }
            lowest
        }

        /// Where a control with `element` was laid out on the last frame, if it was.
        fn control(&self, element: egui::Id) -> Option<Rect> {
            self.ctx.read_response(element).map(|r| r.rect)
        }

        /// Show `tab`, so the pane under test is the one being asked about.
        fn showing(&mut self, tab: TabId) {
            self.selected = tab;
            self.frame(Vec::new());
            self.frame(Vec::new());
        }
        /// Press and release over `at`, reporting what the body said was clicked.
        fn click(&mut self, at: egui::Pos2) -> Option<Click> {
            self.frame(vec![egui::Event::PointerMoved(at)]);
            self.frame(vec![egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            }]);
            self.frame(vec![egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            }])
        }

        /// The top of the LOWEST piece of text reading `text` that a fresh frame paints.
        ///
        /// The selected tab's label is painted twice — once on its chip, once as the pane's own
        /// heading — and the lower of the two is the heading, which is where the content pane
        /// visibly begins. Read off the painted shapes because a heading is text, not a control.
        fn lowest_text_top(&mut self, text: &str) -> Option<f32> {
            fn walk(shape: &egui::Shape, text: &str, lowest: &mut Option<f32>) {
                match shape {
                    egui::Shape::Text(painted) if painted.galley.text() == text => {
                        let top = painted.pos.y;
                        *lowest = Some(lowest.map_or(top, |seen: f32| seen.max(top)));
                    }
                    egui::Shape::Vec(shapes) => {
                        shapes.iter().for_each(|shape| walk(shape, text, lowest));
                    }
                    _ => {}
                }
            }
            self.frame(Vec::new());
            let mut lowest = None;
            for clipped in &self.painted.shapes {
                walk(&clipped.shape, text, &mut lowest);
            }
            lowest
        }

        /// Every chip the body actually placed, in the model's tab order.
        ///
        /// Silently skips a tab it never laid out, so a caller counting rows cannot be misled into
        /// reading a dropped chip as a row that was not needed — the per-tab assertions are what
        /// catch the drop.
        fn chips_ordered(&self, tabs: &[Tab]) -> Vec<Rect> {
            tabs.iter().filter_map(|tab| self.chip(tab.id)).collect()
        }

        /// Where the body put a tab's chip on the last frame, if it put it anywhere.
        fn chip(&self, id: TabId) -> Option<Rect> {
            self.ctx
                .read_response(egui::Id::new(tab_element_id(id)))
                .map(|response| response.rect)
        }
    }

    /// How many consecutive unchanged frames mean a scroll has finished animating.
    ///
    /// One is not enough: the easing has not started yet on the frame after the wheel event, so a
    /// single still frame is what a settled control and a not-yet-moving one both look like.
    const STILL_FRAMES: u32 = 5;

    /// How far one step of the reachability search scrolls, in logical pixels.
    const SCROLL_STEP: f32 = 120.0;

    /// One tab with a label of a chosen length, so a test can decide how much the strip must hold.
    ///
    /// It carries one row, which is what gives the content pane something a test can find.
    fn tab_labelled(id: TabId, label: &str) -> Tab {
        Tab {
            id,
            label: label.to_owned(),
            note: PaneNote::Ready,
            sections: vec![Section {
                heading: Some(format!("{label} section")),
                rows: vec![MenuRow::Action {
                    action: TrayAction::OpenLogs,
                    label: THE_ROW.to_owned(),
                    enabled: true,
                }],
            }],
        }
    }

    /// The one row every synthetic tab carries, so a test can ask where the content pane begins.
    const THE_ROW: &str = "The only row";

    /// Every [`TabId`] there is, labelled long enough that one row cannot hold them.
    ///
    /// Taken from [`TabId::all`] rather than written out, so a tab added upstream is exercised here
    /// without anyone remembering to add it — which is the hazard the derived list closes
    /// (dig_ecosystem#2358). The labels are deliberately equal and long, because a label is model
    /// data: a longer word, or a translation of the same word, must not be able to delete a tab.
    ///
    /// The label GREW when the tab set shrank from seven to five. Five chips of `"Configuration"`
    /// fit comfortably on one row at every width tested here, which would have made this fixture
    /// answer "does the strip wrap" with a strip that never wrapped. The vacuity guard in
    /// [`every_tab_is_reachable_at_every_width_the_window_allows`] is what caught that rather than
    /// letting the property quietly stop being tested — and it is why the length is stated against
    /// the widest width the test drives, not chosen by eye.
    fn a_strip_that_cannot_fit_on_one_row() -> Vec<Tab> {
        TabId::all()
            .into_iter()
            .map(|id| tab_labelled(id, OVERFLOWING_LABEL))
            .collect()
    }

    /// A tab label long enough that [`TabId::all`]-many of them cannot share one row at
    /// [`NARROW_AT`] — the widest window the narrow strip is ever drawn in.
    const OVERFLOWING_LABEL: &str = "Configuration and options";

    /// **A strip that wrapped onto a second row pushes the content pane down, rather than over it.**
    ///
    /// The strip's height is an OUTPUT of its layout, and a split that kept assuming one row would
    /// hand the pane a rectangle the second row of chips is already sitting in — every tab
    /// reachable, and the first thing under them unreadable. Asserted on the real rects of both, so
    /// a strip that grows and a pane that does not is a failure rather than a fresh screenshot.
    #[test]
    fn a_wrapped_strip_moves_the_content_pane_down_instead_of_overlapping_it() {
        let tabs = a_strip_that_cannot_fit_on_one_row();
        let mut body = Body::holding(tabs.clone(), super::super::shell::SHELL_MIN);
        body.frame(Vec::new());

        let lowest_chip = tabs
            .iter()
            .filter_map(|tab| body.chip(tab.id))
            .map(|chip| chip.bottom())
            .fold(f32::MIN, f32::max);
        let heading = body
            .lowest_text_top(&tabs[0].label)
            .expect("the selected tab's pane heading is painted");

        assert!(
            lowest_chip > STRIP_HEIGHT,
            "the fixture did not wrap, so this proves nothing: the lowest chip ends at \
             {lowest_chip}, inside a single {STRIP_HEIGHT} px row"
        );
        assert!(
            heading >= lowest_chip,
            "the pane's heading starts at {heading}, above the last chip row which ends at \
             {lowest_chip} — the strip grew and the content pane did not move"
        );
    }

    /// **A tab the model emits is reachable at every width the window can be dragged to.**
    ///
    /// The property, said once: a tab that exists can be clicked. It is asserted on the chip's own
    /// geometry and on a real click landing on it — not on its label appearing somewhere in the
    /// frame, which is what the shell's own reachability test used to do and which a chip laid out
    /// past the right edge, or under another chip, satisfies just as well.
    ///
    /// The vacuity guard is the point of the fixture: a strip whose chips all fit says nothing about
    /// overflow, so the test refuses to pass unless the labels genuinely overflow one row.
    #[test]
    fn every_tab_is_reachable_at_every_width_the_window_allows() {
        let widths = [
            super::super::shell::SHELL_MIN,
            NARROW_AT - 1.0,
            (super::super::shell::SHELL_MIN + NARROW_AT) / 2.0,
        ];
        for width in widths {
            let tabs = a_strip_that_cannot_fit_on_one_row();
            let mut body = Body::holding(tabs.clone(), width);

            let natural: f32 = tabs
                .iter()
                .map(|tab| {
                    body.ctx.fonts(|f| {
                        f.layout_no_wrap(
                            tab.label.clone(),
                            semibold(size::SM),
                            egui::Color32::WHITE,
                        )
                        .size()
                        .x
                    }) + space::S4
                        + space::S2 / 2.0
                })
                .sum();
            assert!(
                natural > width,
                "at {width} px the chips need only {natural} px, so nothing overflows and this \
                 test proves nothing"
            );

            for tab in &tabs {
                let chip = body
                    .chip(tab.id)
                    .unwrap_or_else(|| panic!("at {width} px {:?} was never laid out", tab.id));
                assert!(
                    Rect::from_min_size(egui::Pos2::ZERO, body.size).contains_rect(chip),
                    "at {width} px {:?} was laid out at {chip:?}, off the window",
                    tab.id
                );
                assert_eq!(
                    body.click(chip.center()),
                    Some(Click::Tab(tab.id)),
                    "at {width} px a click on {:?}'s chip did not select it",
                    tab.id
                );
            }
        }
    }

    /// **At the smallest window a person can make, every tab the SHIPPING model emits is clickable
    /// — Settings included.**
    ///
    /// The overflow property above is proved on a synthetic strip: seven equal-length
    /// `"Configuration"` chips, and `Advanced` standing in for the seventh because that fixture
    /// predates Settings. That fixture answers "does the strip wrap", which is the layout's
    /// question. It cannot answer "does the tab I added arrive at the layout at all" — a
    /// [`crate::window_model::build`] that stopped emitting Settings, or a strip keyed on a list of
    /// ids that was never extended, leaves that test untouched and green while the feature has no
    /// route to it.
    ///
    /// So this one drives the real builder with the real labels, whose widths are unequal and none
    /// of which the layout test ever sees, and pins the tab by id rather than by position.
    ///
    /// It runs that set twice. **As shipped** the seven English labels fit one row at the minimum
    /// width with a little to spare — measured, not assumed, and the second case exists precisely
    /// because of it: a test that only ran the shipping labels would never reach the wrap path, so
    /// restoring the drop-on-overflow bug would leave it green. **Translated** lengthens every label
    /// and so forces the wrap, with a guard that refuses to pass if it did not.
    #[test]
    fn the_shipping_tab_set_reaches_settings_at_the_smallest_window() {
        let view = crate::tray_menu::TrayView {
            running: true,
            update: Some(crate::auto_update::BeaconStatus {
                paused: false,
                schedule_opted_out: false,
                channel: crate::auto_update::UpdateChannel::Stable,
            }),
            ..Default::default()
        };
        let shipped = crate::window_model::build(&view).tabs;

        // Without this every loop below is satisfied by a model that dropped Settings entirely,
        // which is the exact regression the test exists to catch.
        assert!(
            shipped.iter().any(|tab| tab.id == TabId::Settings),
            "the shipping model no longer emits a Settings tab, so its reachability is moot"
        );

        // A label is model data, and German is not a hypothetical: the ids and the count stay the
        // shipping ones, only the words get longer.
        let translated: Vec<Tab> = shipped
            .iter()
            .map(|tab| Tab {
                label: format!("{} {}", tab.label, tab.label),
                ..tab.clone()
            })
            .collect();

        let width = super::super::shell::SHELL_MIN;
        for (case, tabs) in [("as shipped", &shipped), ("translated", &translated)] {
            let mut body = Body::holding(tabs.clone(), width);
            if case == "translated" {
                let rows = body
                    .chips_ordered(tabs)
                    .iter()
                    .map(|chip| chip.top().to_bits())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len();
                assert!(
                    rows > 1,
                    "the translated labels still fit on one row, so this case never reaches the \
                     wrap path and proves nothing"
                );
            }
            for tab in tabs {
                let chip = body.chip(tab.id).unwrap_or_else(|| {
                    panic!(
                        "{case}, at the minimum width, {:?} was never laid out",
                        tab.id
                    )
                });
                assert!(
                    Rect::from_min_size(egui::Pos2::ZERO, body.size).contains_rect(chip),
                    "{case}, at the minimum width, {:?} was laid out at {chip:?}, off the window",
                    tab.id
                );
                assert_eq!(
                    body.click(chip.center()),
                    Some(Click::Tab(tab.id)),
                    "{case}, at the minimum width, a click on {:?}'s chip did not select it",
                    tab.id
                );
            }
        }
    }
    /// **Every verb a tab CLAIMS to offer can actually be pressed, at the narrowest width there is.**
    ///
    /// `Tab::actions()` enumerates what the window offers, and the shell's reachability invariant is
    /// stated against it. Before dig_ecosystem#2327 the pane clamped its content at the bottom edge
    /// and simply stopped drawing, so at 480x480 the Account tab's last verbs were enumerated as
    /// offered and were not on screen at all - a claim the surface could not keep.
    ///
    /// Asserted on geometry plus a REAL click, never on painted text (dig_ecosystem#2320): a label
    /// in the shape list says nothing about whether the control is visible or hit-testable, and this
    /// is precisely the case where those come apart. The pane is scrolled until each control is in
    /// the viewport, which is what a person does, and then clicked.
    ///
    /// The vacuity guard matters here more than anywhere: the Account tab at 480x480 must genuinely
    /// hold more content than fits, or a pane that never scrolled would pass.
    #[test]
    fn every_verb_a_tab_offers_can_be_pressed_at_the_narrowest_width() {
        let view = TrayView {
            running: true,
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            ..TrayView::default()
        };
        let model = crate::window_model::build(&view);
        let mut body = Body::holding(model.tabs.clone(), super::super::shell::SHELL_MIN);
        body.facts = PaneFacts::of_tray(&view);

        for tab in &model.tabs {
            let claimed = tab.actions();
            if claimed.is_empty() {
                continue;
            }
            body.showing(tab.id);

            // The label a verb is drawn under, paired with the id the pane gives that row. Read off
            // the model rather than guessed, so a relabelled row does not silently stop being tested.
            let mut seen = std::collections::HashMap::<String, usize>::new();
            let mut wanted = Vec::new();
            for section in &tab.sections {
                for row in &section.rows {
                    if let MenuRow::Action {
                        action,
                        label,
                        enabled,
                    } = row
                    {
                        let occurrence = seen.entry(label.clone()).or_insert(0);
                        wanted.push((
                            *action,
                            *enabled,
                            pane::row_element_id(label, *occurrence),
                            label.clone(),
                        ));
                        *occurrence += 1;
                    }
                }
            }

            // The CONTENT pane, not the window: a row hidden behind the status band along the
            // bottom is not reachable, and the wheel has to be aimed somewhere the scroll area
            // actually is (dig_ecosystem#3007).
            let viewport = body.content;
            let probe = viewport.center();
            for (action, enabled, element, label) in wanted {
                let rect = body
                    .scroll_into_view(element, probe, viewport)
                    .unwrap_or_else(|| {
                        panic!(
                            "{:?} claims to offer {action:?} ({label:?}) but no amount of                              scrolling brought it fully on screen at {} px",
                            tab.id,
                            crate::confirm::gui::window::shell::SHELL_MIN
                        )
                    });
                if enabled {
                    assert_eq!(
                        body.click(rect.center()),
                        Some(Click::Act(action)),
                        "{:?}: a click on {label:?} at {rect:?} did not run it",
                        tab.id
                    );
                }
            }
        }
    }

    /// **The status readings are never above the content, at either width**
    /// (dig_ecosystem#3007).
    ///
    /// The move's whole point, asserted as geometry at BOTH layouts because they place the readings
    /// differently and only one of them is "under the sidebar": wide, they are in the navigation
    /// column beside the content; narrow, they are in a band beneath it. What must hold in both is
    /// that no reading is drawn between the top of the window and the page.
    #[test]
    fn the_status_readings_are_never_drawn_above_the_content() {
        let view = TrayView {
            running: true,
            node_connected: true,
            ..TrayView::default()
        };
        let model = crate::window_model::build(&view);
        for width in [super::super::shell::SHELL_MIN, 960.0] {
            let mut body = Body::holding(model.tabs.clone(), width);
            body.facts = PaneFacts::of_tray(&view);
            body.frame(Vec::new());

            let node = body
                .lowest_text_top(super::pane::facts::NODE_CONNECTED)
                .unwrap_or_else(|| panic!("the node reading is missing entirely at {width} px"));
            let content = body.content;
            assert!(
                node >= content.top() || width >= NARROW_AT,
                "at {width} px a status reading is drawn at y={node}, above the content pane which \
                 starts at {}",
                content.top()
            );
            if width < NARROW_AT {
                assert!(
                    node >= content.bottom() - 0.5,
                    "at {width} px the readings are at y={node}, not in the band below the content \
                     pane which ends at {}",
                    content.bottom()
                );
            } else {
                assert!(
                    node > content.top() + content.height() / 2.0,
                    "at {width} px the readings are at y={node}, not at the FOOT of the sidebar"
                );
            }
        }
    }

    /// **A pane cannot be scrolled past its own content** (dig_ecosystem#3009).
    ///
    /// Scrolled as far as the wheel will take it, the LAST thing the pane draws must still be on
    /// screen: the person is at the end of the content, so the content is what they are looking at.
    /// Before this, the pane could be dragged on into blank space — a screenful of nothing, with no
    /// cue that you had gone past the end and nothing to scroll back TO except by reversing.
    ///
    /// Asserted on the last ROW rather than on a scroll offset, because the offset is the mechanism
    /// and this is a claim about what a person sees. The tolerance is the pane's own bottom padding
    /// and no more; a pane clamped to the wrong thing — the viewport, or a remembered maximum —
    /// leaves the last row hundreds of pixels up, which no padding allowance can absorb.
    #[test]
    fn a_pane_cannot_be_scrolled_past_its_last_row() {
        let view = TrayView {
            running: true,
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            ..TrayView::default()
        };
        let model = crate::window_model::build(&view);
        // Every tab, not only the tall one: overscroll is a property of the scroll surface, and the
        // surface is shared. Both kinds have to appear or the test is only half exercised, which is
        // what the two counters below are for.
        let (mut scrolling_panes, mut short_panes) = (0, 0);
        // The third size is deliberately TALLER than any pane's content, because a window that is
        // never big enough leaves the short-pane half of this property untested — which is exactly
        // what the counters caught on the first run of this test.
        for size in [
            Vec2::splat(super::super::shell::SHELL_MIN),
            Vec2::new(960.0, 640.0),
            Vec2::new(1_200.0, 2_000.0),
        ] {
            let width = size.x;
            let mut body = Body::holding(model.tabs.clone(), width);
            body.size = size;
            body.facts = PaneFacts::of_tray(&view);

            for tab in &model.tabs {
                body.showing(tab.id);
                let probe = body.content.center();
                body.scroll_to_the_top(probe);
                let at_rest = body
                    .lowest_ink()
                    .unwrap_or_else(|| panic!("{:?} at {width} px drew nothing at all", tab.id));
                body.scroll_to_the_end(probe);
                let at_the_end = body.lowest_ink().unwrap_or_else(|| {
                    panic!(
                        "{:?} at {width} px scrolled to a screen with no content on it at all: \
                         the person is past the end of the pane, looking at blank space",
                        tab.id
                    )
                });

                // A pane SHORTER than its viewport does not move under the wheel at all, and that
                // is the correct behaviour rather than a case to bound: "scroll it until it reaches
                // the bottom" is the opposite fix. Told apart by whether the wheel MOVED anything,
                // not by comparing heights — the trailing card's own padding sits below the last
                // word, so a height comparison misreads a scrolling pane as a short one.
                if at_the_end == at_rest {
                    short_panes += 1;
                    continue;
                }

                let blank = body.content.bottom() - at_the_end;
                assert!(
                    blank <= TRAILING_BLANK,
                    "{:?} at {width} px scrolled {blank} px past the end of its content — the                      person is looking at empty space",
                    tab.id
                );
                scrolling_panes += 1;
            }
        }
        assert!(
            scrolling_panes > 0 && short_panes > 0,
            "the fixture exercised {scrolling_panes} scrolling and {short_panes} short panes, so \
             one of the two halves of this property was never tested"
        );
    }

    /// How much blank a correctly clamped pane may still show under its last WORD.
    ///
    /// Not zero, and the reason is measurable: the last word sits inside a card, so the card's own
    /// bottom padding and the pane's trailing `space::S5` are legitimately below it. Measured
    /// across every tab at every size this test drives, the largest is 67.5 px (Account at 480 px);
    /// 80 leaves room for a card gaining a step of padding without loosening the bound to the point
    /// where it stops meaning anything.
    ///
    /// The bound is pinned from BOTH sides. The defect this test exists for produces a screen with
    /// no content on it whatsoever — the `unwrap_or_else` above fails first, and does so on the
    /// unfixed code — so this bound catches the milder version: a clamp that is merely a little too
    /// generous.
    const TRAILING_BLANK: f32 = 80.0;

    /// **The Account tab at `SHELL_MIN` genuinely does not fit, so the test above is not vacuous.**
    ///
    /// Its own test rather than an assertion inside the loop, because the fixture's overflow is the
    /// premise of the reachability property and deserves to fail by its own name when it stops
    /// holding - a pane that shrank until everything fitted would otherwise make the guarantee
    /// quietly untested rather than break it.
    #[test]
    fn the_reachability_fixture_holds_more_than_one_screen_of_content() {
        let view = TrayView {
            running: true,
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            ..TrayView::default()
        };
        let model = crate::window_model::build(&view);
        let account = model
            .tab(TabId::Account)
            .expect("the Account tab is emitted for an unlocked account");
        let mut body = Body::holding(model.tabs.clone(), super::super::shell::SHELL_MIN);
        body.facts = PaneFacts::of_tray(&view);
        body.showing(TabId::Account);

        let last = account
            .sections
            .iter()
            .flat_map(|section| &section.rows)
            .filter_map(|row| match row {
                MenuRow::Action { label, .. } => Some(label.clone()),
                _ => None,
            })
            .next_back()
            .expect("the Account tab has rows");
        let viewport = Rect::from_min_size(egui::Pos2::ZERO, body.size);
        let on_screen = body
            .control(pane::row_element_id(&last, 0))
            .is_some_and(|rect| viewport.contains_rect(rect));
        assert!(
            !on_screen,
            "the Account tab's last verb ({last:?}) fits on one {} px screen without scrolling, so              the reachability test no longer exercises the scroll path",
            super::super::shell::SHELL_MIN
        );
    }
}
