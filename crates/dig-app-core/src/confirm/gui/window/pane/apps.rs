//! The Apps tab: one card per DIG app this install can open.
//!
//! # Why a card and not a row
//!
//! The tray can offer a name. A card can say what the app IS before a person decides to open it,
//! which is the difference between a menu and an application (dig_ecosystem#2326). The sentence
//! comes from the registry ([`crate::apps::DigApp::tagline`]) so a second app is still a data row —
//! the property [`crate::apps`] was built around — and never new pane code.
//!
//! # What this pane deliberately does NOT show
//!
//! **Whether an app is installed.** Presence is discovered inside the click, by
//! [`crate::apps::plan_launch`], and this window cannot read it (dig_ecosystem#2330). So there is no
//! state chip: an "Installed" pill drawn from a guess is exactly the placeholder-that-looks-real
//! this epic exists to remove, and greying an absent app would ALSO contradict the model, which
//! emits every app's row ENABLED on purpose — the click always does something visible, either a
//! launch or an honest notice (#1800). The tab says instead how apps arrive and what a click will
//! tell you, which is everything a person can act on.
//!
//! **A version per app.** No source for one exists, and spawning every app at paint time to ask
//! would make drawing this tab start processes.

use super::action::{self, Action};
use super::card;
use super::copy;
use super::flow::Flow;
use super::text;
use crate::apps::DigApp;
use crate::confirm::gui::render::space;
use crate::confirm::gui::theme::Tokens;
use crate::tray_menu::TrayAction;
use crate::window_model::Tab;

/// Draw the Apps pane's content into `flow`, and report the action pressed.
pub(crate) fn draw(flow: &mut Flow, t: &Tokens, tab: &Tab) -> Option<TrayAction> {
    flow.place(|ui, at| (text::body(ui, at, t, copy::apps::LEAD), ()));
    flow.gap(space::S4);

    let mut pressed = None;
    let verbs = split_by_app(super::actions_of(tab));

    for card in verbs.apps {
        pressed = pressed.or(app_card(flow, t, card.app, card.open));
        flow.gap(space::S4);
    }
    pressed = pressed.or(other_card(flow, t, &verbs.other));

    flow.place(|ui, at| (text::caption(ui, at, t, copy::apps::INSTALL_NOTE), ()));
    pressed
}

/// One app card: the registry entry, and the model's verb for opening it.
struct AppCard {
    /// The entry the verb's [`crate::apps::AppId`] resolves to — the card's name and sentence.
    app: &'static DigApp,
    /// The model's launch row, unchanged.
    open: Action<TrayAction>,
}

/// A tab's verbs, sorted into the cards that draw them.
struct TabVerbs {
    /// One per launch row, in the model's order.
    apps: Vec<AppCard>,
    /// Everything else the model put on this tab.
    other: Vec<Action<TrayAction>>,
}

/// Split a tab's verbs into the ones that open a registered app and the ones that do not.
///
/// # Why the split is on the ACTION and not on the section
///
/// A card needs the registry row behind a verb — its name and its sentence — and only
/// [`TrayAction::LaunchApp`] carries the id that finds one. Anything else the model puts on this tab
/// is still rendered, in its own card, rather than dropped: this pane may not decide that a verb the
/// model offered is not worth showing.
fn split_by_app(actions: Vec<Action<TrayAction>>) -> TabVerbs {
    let mut verbs = TabVerbs {
        apps: Vec::new(),
        other: Vec::new(),
    };
    for action in actions {
        match action.id {
            TrayAction::LaunchApp(id) => verbs.apps.push(AppCard {
                app: crate::apps::app(id),
                open: action,
            }),
            _ => verbs.other.push(action),
        }
    }
    verbs
}

/// One app: its name, what it is, and the model's own verb for opening it.
///
/// The button's label is the model's, VERBATIM. It reads as the app's name because that is what the
/// tray decided to call this verb, and re-wording it here — to "Open Chat", say — would give the
/// window a second vocabulary for the same decision and take away any explanation a future label
/// carries (`super::action` states that rule; a disabled row's label is where its remedy lives).
fn app_card(
    flow: &mut Flow,
    t: &Tokens,
    app: &'static DigApp,
    action: Action<TrayAction>,
) -> Option<TrayAction> {
    let live = flow.live();
    flow.place(|ui, at| {
        let (height, pressed) =
            card::interactive_card(ui, at, t, live, Some(app.display_name), |inner| {
                inner.place(|ui, at| (text::body(ui, at, t, app.tagline), ()));
                inner.gap(space::S4);
                inner
                    .place(|ui, at| action::buttons(ui, at, t, live, std::slice::from_ref(&action)))
            });
        (height, pressed.flatten())
    })
}

/// Whatever else the model put on this tab, in one card so nothing is lost.
///
/// Empty today — [`crate::tray_menu::apps_actions`] emits nothing but launches — and drawn from the
/// leftovers rather than assumed absent, because "the model can only ever offer app rows here" is a
/// claim about upstream code that this pane has no way to keep.
fn other_card(flow: &mut Flow, t: &Tokens, actions: &[Action<TrayAction>]) -> Option<TrayAction> {
    if actions.is_empty() {
        return None;
    }
    let live = flow.live();
    let pressed = flow.place(|ui, at| {
        let (height, pressed) =
            card::interactive_card(ui, at, t, live, Some(copy::apps::OTHER_CARD), |inner| {
                inner.place(|ui, at| action::buttons(ui, at, t, live, actions))
            });
        (height, pressed.flatten())
    });
    flow.gap(space::S4);
    pressed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::AppId;
    use crate::confirm::gui::render::Weight;
    use crate::tray_menu::{MenuRow, TrayView};
    use crate::window_model::{Section, TabId};

    /// The real Apps tab, as the shipping model builds it.
    fn shipping_tab() -> Tab {
        crate::window_model::build(&TrayView::default())
            .tab(TabId::Apps)
            .expect("the Apps tab is always emitted")
            .clone()
    }

    /// **Every launch row becomes its own card, paired with the entry its action names, and a verb
    /// that is not a launch is kept rather than dropped.**
    ///
    /// What this CANNOT prove, said plainly: the registry holds exactly one app today
    /// ([`crate::apps::APPS`]), so a pairing by POSITION and a pairing by id agree on every fixture
    /// that can be written — a second [`AppId`] variant does not exist to disagree with. The
    /// mis-pairing is instead ruled out by construction, since [`split_by_app`] looks the entry up
    /// from the id the action carries; this test pins the parts a fixture can still exhibit, and the
    /// duplicate-label pair is the one that has genuinely broken before (two cards, one element id).
    #[test]
    fn each_app_row_is_paired_with_the_registry_entry_its_action_names() {
        let launch = |label: &str| MenuRow::Action {
            action: TrayAction::LaunchApp(AppId::Chat),
            label: label.to_string(),
            enabled: true,
        };
        let tab = Tab {
            id: TabId::Apps,
            label: "Apps".to_string(),
            note: crate::window_model::PaneNote::Ready,
            sections: vec![Section {
                heading: None,
                rows: vec![
                    launch("Chat"),
                    MenuRow::Action {
                        action: TrayAction::OpenLogs,
                        label: "Open the log folder".to_string(),
                        enabled: true,
                    },
                    launch("Chat"),
                ],
            }],
        };

        let verbs = split_by_app(super::super::actions_of(&tab));
        assert_eq!(verbs.apps.len(), 2, "an app row did not become a card");
        for card in &verbs.apps {
            assert_eq!(card.open.id, TrayAction::LaunchApp(card.app.id));
        }
        assert_ne!(
            verbs.apps[0].open.element, verbs.apps[1].open.element,
            "two rows with the same label share an element id, which egui reports as a duplicate \
             and which leaves one card's button unclickable"
        );
        assert_eq!(
            verbs.other.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![TrayAction::OpenLogs],
            "a verb the model offered was dropped instead of being drawn in its own card"
        );
    }

    /// **The pane renders exactly the verbs the model put on the tab — no more, no fewer.**
    ///
    /// Asserted against the real builder, so the day the Apps tab gains a row upstream this test
    /// covers it without being edited.
    #[test]
    fn the_pane_offers_the_models_verbs_and_nothing_else() {
        let tab = shipping_tab();
        let verbs = split_by_app(super::super::actions_of(&tab));
        let rendered: Vec<TrayAction> = verbs
            .apps
            .into_iter()
            .map(|card| card.open.id)
            .chain(verbs.other.into_iter().map(|action| action.id))
            .collect();
        assert_eq!(rendered, tab.actions());
        assert!(
            !rendered.is_empty(),
            "the shipping Apps tab offers nothing, so this proves nothing"
        );
    }

    /// **An app's card button carries the model's label unchanged, and the model's enablement.**
    ///
    /// The pane must not decide that an app is unavailable — `apps_actions` emits every row ENABLED
    /// on purpose, because the click always does something visible (#1800), and a card that greyed
    /// an absent app would be this pane answering a question it cannot read (dig_ecosystem#2330).
    #[test]
    fn a_card_neither_rewords_its_verb_nor_greys_it_out() {
        let tab = shipping_tab();
        let verbs = split_by_app(super::super::actions_of(&tab));
        let card = verbs
            .apps
            .first()
            .expect("the registry has at least one app");
        let (entry, action) = (card.app, &card.open);

        let label = tab
            .sections
            .iter()
            .flat_map(|section| &section.rows)
            .find_map(|row| match row {
                MenuRow::Action {
                    action: TrayAction::LaunchApp(id),
                    label,
                    ..
                } if *id == entry.id => Some(label.clone()),
                _ => None,
            })
            .expect("the model offers a launch row for the first registry app");
        assert_eq!(action.label, label, "the pane re-worded the model's label");
        assert!(action.enabled, "the pane greyed an app the model offered");
        assert_eq!(
            action.weight,
            Weight::Primary,
            "the leading enabled verb on the tab is not the pane's primary control"
        );
    }

    /// **The tab's closing line answers where apps come from without claiming any is installed.**
    ///
    /// The words that would be a lie are the ones a presence chip would use. Pinned as an absence
    /// over the tab's whole copy rather than by inspecting one constant, so moving the sentence
    /// between constants cannot lose the guarantee.
    #[test]
    fn no_copy_on_this_tab_claims_an_app_is_installed_or_missing() {
        let said = format!(
            "{} {} {}",
            copy::apps::LEAD,
            copy::apps::INSTALL_NOTE,
            crate::apps::APPS[0].tagline
        )
        .to_lowercase();
        for claim in ["installed on this computer", "not installed", "missing"] {
            assert!(
                !said.contains(claim),
                "the Apps tab says {claim:?}, which is presence — a fact this window cannot read"
            );
        }
        assert!(
            said.contains("installed alongside"),
            "the tab never says how apps arrive, which is the question a person asks here"
        );
    }

    /// **The drawn pane puts every app in a card of its own, and never loses a verb that is not an
    /// app.**
    ///
    /// The unit tests above pin the sort; this draws the real pane at `SHELL_MIN` and reads what the
    /// painter was asked for, which is where a card that measured itself wrongly or a group that was
    /// composed and never placed would show up. The fixture carries a non-launch verb precisely
    /// because the shipping model has none — the leftover card exists so a verb added upstream cannot
    /// vanish, and a path nothing exercises is a path nobody knows is broken.
    #[test]
    fn the_drawn_pane_gives_each_app_a_card_and_keeps_a_verb_that_is_not_one() {
        let mut tab = shipping_tab();
        tab.sections.push(Section {
            heading: None,
            rows: vec![MenuRow::Action {
                action: TrayAction::OpenLogs,
                label: "Open the log folder".to_string(),
                enabled: true,
            }],
        });

        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let t = crate::confirm::gui::theme::Theme::Light.tokens();
        let facts = super::super::facts::PaneFacts::of_tray(&TrayView::default());
        let width = super::super::super::shell::SHELL_MIN;
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::Vec2::new(width, 4_000.0));

        let mut output = egui::FullOutput::default();
        // Two frames: the first builds the font atlas, the second lays out against it.
        for _ in 0..2 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("apps-pane-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            let column = egui::Rect::from_min_size(
                                screen.left_top(),
                                egui::Vec2::new(width - space::S5 * 2.0, f32::INFINITY),
                            );
                            super::super::draw_tab(ui, column, &t, &tab, &facts, true);
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
        let all = said.join(" | ");

        let entry = crate::apps::APPS[0];
        assert!(
            all.contains(entry.display_name),
            "no card for an app: {all}"
        );
        assert!(
            all.contains(entry.tagline),
            "a card drew an app's name without saying what it is: {all}"
        );
        assert!(
            all.contains(copy::apps::OTHER_CARD) && all.contains("Open the log folder"),
            "a verb that is not an app launch was dropped rather than kept in its own card: {all}"
        );
        assert!(
            all.contains(copy::apps::INSTALL_NOTE),
            "the tab did not say how apps arrive: {all}"
        );
    }
}
