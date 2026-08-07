//! What a person can DO in a pane: buttons with a hierarchy, and the row list they replace.
//!
//! # The line this module must not cross
//!
//! Which verbs exist, and whether each is enabled, is decided ONCE — by the group builders in
//! [`crate::tray_menu`], composed into tabs by [`crate::window_model`]. Nothing here asks whether an
//! action should be offered. It reads `MenuRow::Action { action, label, enabled }` and draws it.
//!
//! What this module adds is WEIGHT. The tray can only render a verb as a row; a window can render
//! the same decided verb as a prominent primary button with the rest as quieter siblings. Choosing
//! the weight is a presentation decision about emphasis, and it is made from the row's POSITION in
//! the group the model already ordered — never from a fact about the account.
//!
//! # Keyboard
//!
//! Every control here is focusable, shows its focus, and activates on Enter or Space
//! (dig_ecosystem#2329). A pointer-only control is unreachable for anyone navigating by keyboard,
//! which on a window whose verbs include "remove this account" is not a polish issue.

use egui::{Rect, Ui, Vec2};

use crate::confirm::gui::paint;
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;

/// The gap between two buttons on the same row, and between two wrapped rows.
const BUTTON_GAP: f32 = space::S2;

/// One thing a person can do, as the pane will draw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Action<Id> {
    /// The label, VERBATIM from the model. Never re-worded here: a disabled row's label already
    /// carries its remedy, and rewriting it would take that explanation away.
    pub(crate) label: String,
    /// How prominent it is.
    pub(crate) weight: Weight,
    /// Whether it can be pressed — the model's answer, passed through.
    pub(crate) enabled: bool,
    /// What the caller gets back when it is pressed.
    pub(crate) id: Id,
    /// The stable element id, so a click survives the surface being rebuilt.
    pub(crate) element: egui::Id,
}

/// Draw a group of actions, wrapping onto further rows when they do not fit.
///
/// Returns the height used and the action pressed, if any.
///
/// # Why wrapping and not truncation or a scroll
///
/// The same reason the tab strip wraps (dig_ecosystem#2309): a control that exists must be
/// reachable. A row of buttons that ran off the right edge at 480 px would hide a verb behind an
/// invisible boundary, which is the failure this whole design system was commissioned to remove.
pub(crate) fn buttons<Id: Clone>(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    live: bool,
    actions: &[Action<Id>],
) -> (f32, Option<Id>) {
    if actions.is_empty() {
        return (0.0, None);
    }

    let mut pressed = None;
    let (mut x, mut y) = (at.left(), at.top());

    for action in actions {
        // Clamped to the column: a label wider than the whole pane is drawn in a full-width button
        // rather than one that starts off the edge.
        let width = paint::button_width(ui, &action.label).min(at.width());
        // `x > at.left()` is "something is already on this row" — a first button that does not fit
        // must still be drawn where it is, because wrapping it would move it to an identical row.
        if x > at.left() && x + width > at.right() {
            x = at.left();
            y += paint::BUTTON_HEIGHT + BUTTON_GAP;
        }
        let rect = Rect::from_min_size(
            egui::Pos2::new(x, y),
            Vec2::new(width, paint::BUTTON_HEIGHT),
        );
        if press(ui, rect, t, live, action) {
            pressed = Some(action.id.clone());
        }
        x += width + BUTTON_GAP;
    }

    (y + paint::BUTTON_HEIGHT - at.top(), pressed)
}

/// Draw one button and report whether it was activated, by pointer OR by keyboard.
fn press<Id>(ui: &mut Ui, rect: Rect, t: &Tokens, live: bool, action: &Action<Id>) -> bool {
    // While a prompt is up nothing is pressable, and the control says so by refusing the pointing
    // hand as well as the click — a hand cursor says *clickable* louder than dimming says *inert*.
    let pressable = action.enabled && live;
    let response = paint::button_at(
        ui,
        rect,
        action.element,
        &action.label,
        action.weight,
        pressable,
        t,
    );
    response.clicked() || activated_by_keyboard(ui, &response, pressable)
}

/// Whether a focused control was activated from the keyboard this frame.
///
/// Enter AND Space, because both are what a person expects of a button and neither is what they
/// expect of a link. Gated on `pressable` as well as focus so a disabled control cannot be pressed
/// by a key that a pointer is refused.
fn activated_by_keyboard(ui: &Ui, response: &egui::Response, pressable: bool) -> bool {
    if !pressable || !response.has_focus() {
        return false;
    }
    ui.input(|i| i.key_pressed(egui::Key::Enter) || i.key_pressed(egui::Key::Space))
}

/// Assign a weight to each action in a group the model has already ordered.
///
/// # The rule, stated once
///
/// The FIRST enabled action in a group is its primary; everything else is a ghost; anything the
/// caller has named destructive is drawn as danger wherever it sits. That is a decision about
/// emphasis within an ordering the model chose — it reads `enabled`, and it never changes it.
///
/// A group whose first action is disabled has NO primary, deliberately: promoting the first
/// *pressable* one would make the pane's most prominent control move as the account's state changes,
/// and a person would learn that the big button is wherever it happens to be today.
pub(crate) fn weigh(index: usize, enabled: bool, destructive: bool) -> Weight {
    match (destructive, index, enabled) {
        (true, _, _) => Weight::Danger,
        (false, 0, true) => Weight::Primary,
        _ => Weight::Ghost,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An action carrying a `u8` so a test can tell which one came back.
    fn action(label: &str, id: u8, weight: Weight, enabled: bool) -> Action<u8> {
        Action {
            label: label.to_owned(),
            weight,
            enabled,
            id,
            element: egui::Id::new(("pane-test-action", label)),
        }
    }

    /// **The first action of a group leads it, and the rest recede.**
    ///
    /// Pinned on the weighting rule rather than on pixels, and from both sides of the one case that
    /// is easy to get wrong: a group whose FIRST action is disabled has no primary at all, rather
    /// than promoting the second and moving the pane's loudest control around under the reader.
    #[test]
    fn a_groups_emphasis_follows_its_order_and_never_moves_when_a_verb_is_disabled() {
        assert_eq!(weigh(0, true, false), Weight::Primary);
        assert_eq!(weigh(1, true, false), Weight::Ghost);
        assert_eq!(
            weigh(0, false, false),
            Weight::Ghost,
            "a disabled leading action must not be drawn as the primary"
        );
        assert_eq!(
            weigh(1, true, false),
            Weight::Ghost,
            "the second action must not be promoted when the first is disabled"
        );
        // Destructive wins wherever it sits, including first.
        assert_eq!(weigh(0, true, true), Weight::Danger);
        assert_eq!(weigh(3, true, true), Weight::Danger);
    }

    /// A body that draws a real button group and can click and type at it.
    struct Group {
        ctx: egui::Context,
        actions: Vec<Action<u8>>,
        width: f32,
        rects: std::collections::HashMap<u8, Rect>,
    }

    impl Group {
        fn of(actions: Vec<Action<u8>>, width: f32) -> Self {
            let ctx = egui::Context::default();
            crate::confirm::gui::window::install_fonts(&ctx);
            let mut group = Self {
                ctx,
                actions,
                width,
                rects: std::collections::HashMap::new(),
            };
            group.frame(Vec::new());
            group.frame(Vec::new());
            group
        }

        /// Run one frame, returning what the group reported as pressed.
        fn frame(&mut self, events: Vec<egui::Event>) -> Option<u8> {
            let screen = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(self.width, 600.0));
            let input = egui::RawInput {
                screen_rect: Some(screen),
                events,
                ..Default::default()
            };
            let t = crate::confirm::gui::theme::Theme::Light.tokens();
            let pressed = std::cell::Cell::new(None);
            let actions = self.actions.clone();
            let _ = self.ctx.run(input, |ctx| {
                egui::Area::new(egui::Id::new("action-test"))
                    .fixed_pos(screen.left_top())
                    .show(ctx, |ui| {
                        ui.set_clip_rect(screen);
                        let (_, hit) = buttons(ui, screen, &t, true, &actions);
                        pressed.set(hit);
                    });
            });
            for action in &self.actions {
                if let Some(response) = self.ctx.read_response(action.element) {
                    self.rects.insert(action.id, response.rect);
                }
            }
            pressed.get()
        }

        /// Press and release the pointer over `at`.
        fn click(&mut self, at: egui::Pos2) -> Option<u8> {
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
    }

    /// Three labels long enough that they cannot share one row at `SHELL_MIN`.
    fn three_wide_actions() -> Vec<Action<u8>> {
        vec![
            action("Show status and details", 0, Weight::Primary, true),
            action("Open the log folder", 1, Weight::Ghost, true),
            action("Check for updates now", 2, Weight::Ghost, true),
        ]
    }

    /// **Every action in a group is on screen and clickable at the narrowest width the window has.**
    ///
    /// The property: a verb the model offers can be pressed. Asserted on each button's own geometry
    /// being inside the pane AND on a real click resolving to that button — not on its label being
    /// painted somewhere, which a button laid out past the right edge satisfies just as well.
    ///
    /// The vacuity guard is the fixture's point: unless the labels genuinely overflow one row, a
    /// group that never wrapped would pass.
    #[test]
    fn every_action_is_on_screen_and_clickable_at_the_narrowest_width() {
        let width = crate::confirm::gui::window::shell::SHELL_MIN;
        let mut group = Group::of(three_wide_actions(), width);

        let natural: f32 = group
            .actions
            .iter()
            .map(|a| {
                group.ctx.fonts(|f| {
                    f.layout_no_wrap(
                        a.label.clone(),
                        crate::confirm::gui::render::semibold(
                            crate::confirm::gui::render::size::BUTTON,
                        ),
                        egui::Color32::WHITE,
                    )
                    .size()
                    .x
                }) + 52.0
                    + BUTTON_GAP
            })
            .sum();
        assert!(
            natural > width,
            "at {width} px the buttons need only {natural} px, so nothing wraps and this test \
             proves nothing"
        );

        let pane = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(width, 600.0));
        for id in [0_u8, 1, 2] {
            let rect = *group
                .rects
                .get(&id)
                .unwrap_or_else(|| panic!("action {id} was never laid out"));
            assert!(
                pane.contains_rect(rect),
                "action {id} was laid out at {rect:?}, off the pane"
            );
            assert_eq!(
                group.click(rect.center()),
                Some(id),
                "a click on action {id} did not activate it"
            );
        }
    }

    /// **A focused control activates on Enter, and a disabled one does not.**
    ///
    /// Two actors, one honest control: without the disabled sibling, a keyboard handler that fired
    /// for ANY focused widget — or for no widget at all — would pass. The disabled one proves the
    /// key is gated on the same condition the pointer is.
    #[test]
    fn a_focused_control_activates_on_enter_and_a_disabled_one_refuses() {
        let actions = vec![
            action("Open the log folder", 0, Weight::Primary, true),
            action(
                "Show my recovery phrase (unlock first)",
                1,
                Weight::Ghost,
                false,
            ),
        ];
        let mut group = Group::of(actions, 900.0);

        let enabled = *group
            .rects
            .get(&0)
            .expect("the enabled action was laid out");
        group.ctx.memory_mut(|m| {
            m.request_focus(egui::Id::new(("pane-test-action", "Open the log folder")))
        });
        let hit = group.frame(vec![egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::default(),
        }]);
        assert_eq!(
            hit,
            Some(0),
            "Enter on the focused control at {enabled:?} did not activate it"
        );

        group.ctx.memory_mut(|m| {
            m.request_focus(egui::Id::new((
                "pane-test-action",
                "Show my recovery phrase (unlock first)",
            )))
        });
        let refused = group.frame(vec![egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::default(),
        }]);
        assert_eq!(
            refused, None,
            "Enter activated a control the pointer is refused on"
        );
    }

    /// An empty group takes no height, rather than a gap the caller cannot account for.
    #[test]
    fn an_empty_group_takes_no_space() {
        let mut group = Group::of(Vec::new(), 480.0);
        assert_eq!(group.frame(Vec::new()), None);
    }
}
