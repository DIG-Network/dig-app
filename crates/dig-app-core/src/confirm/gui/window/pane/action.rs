//! What a person can DO in a pane: buttons with a hierarchy, and the row list they replace.
//!
//! # The line this module must not cross
//!
//! Which verbs exist, and whether each is enabled, is decided ONCE — by the group builders in
//! [`crate::tray_menu`], composed into tabs by [`crate::window_model`]. Nothing here asks whether an
//! action should be offered. It reads `MenuRow::Action { action, label, enabled }` and draws it.
//!
//! What this module adds is WEIGHT. The tray can only render a verb as a row; a window can render
//! the same decided verb as a prominent primary button with the rest as quieter siblings.
//!
//! Emphasis follows what a control DOES, never where it sits. A destroy is drawn as danger wherever
//! the model put it; everything else is a peer unless a PANE names it as that pane's one lead
//! ([`promote`]). See [`weigh`] for the three defects the older positional rule shipped.
//!
//! # Keyboard
//!
//! Every control here is focusable, shows its focus, and activates on Enter or Space — and none of
//! that is implemented here. egui synthesises a primary click for a focused widget that senses
//! clicks (`Context::create_widget`), so a pane button gets keyboard activation by being an ordinary
//! `Sense::click()` widget, and a DISABLED one is refused the same way it is refused a pointer:
//! `paint::button_at` gives it `Sense::hover()`, and egui's synthesis is gated on `senses_click()`.
//!
//! This module briefly carried its own Enter/Space handler. It was deleted because it was
//! redundant, which the gate proved the only way that is convincing: emptying its body changed
//! nothing, because the behaviour it claimed to add was already there.

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
    // `clicked()` alone, because egui reports a focused widget's Enter or Space as a click. See
    // the module docs: a second implementation here was redundant.
    paint::button_at(
        ui,
        rect,
        action.element,
        &action.label,
        action.weight,
        pressable,
        t,
    )
    .clicked()
}

/// Assign a weight to an action from what it DOES.
///
/// # Emphasis is not a position (dig_ecosystem#2354)
///
/// This used to make the first enabled action of every group the pane's primary, which meant nothing
/// about a control's meaning entered the decision. Three panes were visibly wrong because of it, and
/// the gallery caught all three: Settings' loudest control was *"Turn auto-update off (asks for
/// administrator)…"*, so the most prominent thing on the tab disabled a safety feature; the Account
/// tab's brightest control was a documentation LINK, so the pane's emphasis pointed away from itself;
/// and the Cache tab had to override the rule by hand to stop `256 MiB` being drawn as a
/// recommendation.
///
/// So the default is now the honest one: **nothing is a primary unless a pane says so.** Danger is
/// still decided here, because it follows from the action alone — a destroy is a destroy wherever it
/// sits, and that must not be a per-pane choice anyone can forget to make. A pane that has one verb
/// worth leading with names it through [`promote`]; a pane with none — which is most of them —
/// simply does not call it.
pub(crate) fn weigh(destructive: bool) -> Weight {
    match destructive {
        true => Weight::Danger,
        false => Weight::Ghost,
    }
}

/// Name the ONE action a pane leads with, and draw it as the primary.
///
/// Returns the group unchanged when `lead` names nothing in it, or names something the model has
/// disabled — a disabled primary is a bright control that cannot be pressed, and a pane whose
/// loudest button moves to whatever happens to be pressable today is the defect [`weigh`] describes.
///
/// A destructive action is never promoted. Its weight follows what it does, and a destroy drawn as
/// the friendly affirmative is the one mistake this vocabulary must make impossible.
pub(crate) fn promote<Id: PartialEq>(mut actions: Vec<Action<Id>>, lead: &Id) -> Vec<Action<Id>> {
    if let Some(action) = actions
        .iter_mut()
        .find(|action| &action.id == lead && action.enabled && action.weight != Weight::Danger)
    {
        action.weight = Weight::Primary;
    }
    actions
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

    /// **No position makes an action the primary — only a pane naming it (dig_ecosystem#2354).**
    ///
    /// [`weigh`] no longer takes a position at all, so the old rule is unexpressible rather than
    /// merely unused. What remains checkable is that it never yields `Primary` on its own, and that
    /// danger still follows the action.
    #[test]
    fn weight_alone_never_promotes_anything_and_danger_still_follows_the_action() {
        assert_eq!(weigh(false), Weight::Ghost);
        assert_eq!(weigh(true), Weight::Danger);
    }

    /// **A pane that names its lead gets exactly one primary, and only when it can be pressed.**
    ///
    /// The fixture varies ONE actor at a time against a truthful control. The disabled case is the
    /// one that matters: promoting a verb the model refuses would draw a bright button a person
    /// cannot press, and the group must come back with no primary at all rather than the next
    /// pressable one — which is the moving-emphasis defect stated as an assertion.
    #[test]
    fn naming_a_lead_promotes_it_once_and_refuses_a_verb_the_model_disabled() {
        let group = || {
            vec![
                action("Open the log folder", 0, Weight::Ghost, true),
                action("Check for updates now", 1, Weight::Ghost, true),
            ]
        };

        let led = promote(group(), &1);
        assert_eq!(
            led[1].weight,
            Weight::Primary,
            "the named lead was not drawn as the primary"
        );
        assert_eq!(
            led[0].weight,
            Weight::Ghost,
            "naming one lead promoted a second control as well"
        );
        assert_eq!(
            led.iter().filter(|a| a.weight == Weight::Primary).count(),
            1
        );

        // Naming nothing on the pane leaves the group exactly as it was.
        assert_eq!(promote(group(), &7), group());

        // A disabled lead is refused, and — the control that makes this load-bearing — its enabled
        // sibling is NOT promoted in its place.
        let mut disabled = group();
        disabled[1].enabled = false;
        let refused = promote(disabled, &1);
        assert!(
            refused.iter().all(|a| a.weight != Weight::Primary),
            "a disabled lead was drawn as the pane's brightest control, or its neighbour was \
             promoted in its place"
        );
    }

    /// **A destroy is never promoted, however loudly a pane asks.**
    ///
    /// The one mistake this vocabulary must make impossible: a destroy drawn as the friendly
    /// affirmative. Asserted with the destroy named as the lead, which is the only way it could ever
    /// happen.
    #[test]
    fn a_destroying_verb_cannot_be_promoted_into_the_affirmative() {
        let group = vec![action(
            "Remove this account from this computer…",
            0,
            Weight::Danger,
            true,
        )];
        assert_eq!(promote(group, &0)[0].weight, Weight::Danger);
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

    /// **A focused pane button activates on Enter, and a disabled one refuses.**
    ///
    /// # What this test is FOR, now that the code it was written against is gone
    ///
    /// Keyboard activation is egui'''s, not ours (see the module docs). So this is a DEPENDENCY
    /// claim: it pins that an ordinary `Sense::click()` pane button gets Enter for free, and that a
    /// disabled one — which `paint::button_at` gives `Sense::hover()` — does not. Both halves are
    /// load-bearing: the day egui stops synthesising the click, or the day someone gives a disabled
    /// control a click sense to '''fix''' its hover, this fails and says why.
    ///
    /// It is deliberately NOT a test of a handler of ours. It WAS one, and the gate proved it
    /// vacuous by emptying that handler and watching it stay green — the correct result reported by
    /// the wrong test. The handler is deleted; the claim is now stated honestly.
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
