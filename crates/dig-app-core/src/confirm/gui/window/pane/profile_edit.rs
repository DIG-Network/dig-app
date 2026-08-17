//! The Account tab's **profile editor**: everything a person publishes about themselves
//! (dig_ecosystem#2993).
//!
//! # What this card decides, and what it does not
//!
//! It decides the LAYOUT — which fields appear, in what order, with what said under each — and it
//! owns the FORM: what is currently typed, which field a person is in, and what is wrong with what
//! they typed. A half-typed value is not application state, so it lives here in the frame's own
//! store, exactly as the Settings pane's does.
//!
//! It decides no verb. Whether the editor may be offered at all is
//! [`ProfileEditing`](crate::profile_edit::ProfileEditing), measured off the seams and carried on the
//! view like every other enablement, and the Save control arrives already built from
//! [`crate::tray_menu::profile_edit_actions`]. What this card decides about that control is only
//! whether it is pressable *this frame* — a form with nothing changed in it, or with something wrong
//! in it, has nothing to save — which is a fact about the typing and lives nowhere else.
//!
//! # The empty profile is a real state
//!
//! A profile with no fields set is a working profile somebody has not filled in yet. It is drawn as
//! the form, ready to type into, with a sentence saying so — never as a fault, and never as the
//! spinner that a read still in flight gets. The difference between "holds nothing" and "could not
//! be read" is the one this pane is most careful about, because a person who types their name over a
//! profile the app could not read commits a body missing everything it already held.
//!
//! # What is said before anything is spent
//!
//! Saving costs real money and publishes to a public chain. Both are said in the card, above the
//! control, because a cost revealed after the click has already interrupted somebody who would have
//! declined.

use egui::Ui;

use super::action::{self, Action};
use super::card;
use super::copy;
use super::facts::PaneFacts;
use super::flow::Flow;
use super::profile_form::{self, Form, Scope};
use super::state::{self, PaneState};
use super::text;
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::profile_edit::{EditService, ProfileDraft, ProfileEditing, ProfileReading};
use crate::tray_menu::TrayAction;
use crate::window_model::Tab;

/// Draw the profile editor, and report the verb pressed.
pub(crate) fn card(
    flow: &mut Flow,
    t: &Tokens,
    tab: &Tab,
    facts: &PaneFacts,
) -> Option<TrayAction> {
    let offer = facts.profile_editing;
    let verbs = save_verbs(tab);
    let live = flow.live();

    flow.place(|ui, at| {
        let (height, pressed) =
            card::interactive_card(ui, at, t, live, Some(copy::profile_edit::CARD), |inner| {
                content(inner, t, offer, &verbs)
            });
        (height, pressed.flatten())
    })
}

/// The card's body: the blocker that explains itself, or the form.
fn content(
    flow: &mut Flow,
    t: &Tokens,
    offer: ProfileEditing,
    verbs: &[Action<TrayAction>],
) -> Option<TrayAction> {
    if !offer.is_possible() {
        let state = match offer.blocked() {
            Some(why) => PaneState::Unreachable(why.sentence().to_string()),
            // Nobody has measured this yet, so the card says it is still looking — never a cause.
            None => PaneState::Waiting(copy::profile_edit::MEASURING.to_string()),
        };
        flow.place(|ui, at| (state::banner(ui, at, t, &state), ()));
        return None;
    }

    let service = EditService::app();
    // Asked for on every frame and started at most once: the service holds the in-flight guard, so
    // a pane that repaints twice a second does not open a chain read twice a second.
    service.refresh();
    let reading = service.reading();

    match &reading {
        ProfileReading::Pending => {
            let waiting = PaneState::Waiting(copy::profile_edit::READING.to_string());
            flow.place(|ui, at| (state::banner(ui, at, t, &waiting), ()));
            None
        }
        ProfileReading::Unreadable(why) => unreadable(flow, t, why),
        // Neither of these is weather and neither has a retry: asking again cannot produce content
        // nobody wrote, and cannot make a contradicted body agree with the chain. Drawing them
        // through `unreadable` would put a *try reading it again* control under both
        // (dig_ecosystem#3036).
        ProfileReading::Unpublished => settled_state(
            flow,
            t,
            PaneState::Empty(crate::profile_edit::copy::UNPUBLISHED.to_string()),
        ),
        ProfileReading::Inconsistent => settled_state(
            flow,
            t,
            PaneState::Unreachable(crate::profile_edit::copy::INCONSISTENT.to_string()),
        ),
        ProfileReading::Known(committed) => form(flow, t, committed, verbs),
    }
}

/// A state that is settled: it is said, and nothing is offered for it.
///
/// The absence of a control is the point. A read that FAILED gets a retry because asking again can
/// change the answer; a profile that has published nothing, and one whose content contradicts the
/// chain, cannot be changed by asking — so a control here would be one a person presses forever.
fn settled_state(flow: &mut Flow, t: &Tokens, state: PaneState) -> Option<TrayAction> {
    flow.place(|ui, at| (state::banner(ui, at, t, &state), ()));
    None
}

/// A profile that could not be read: what happened, and the one control that helps.
///
/// The retry is built HERE rather than in the model, and it is the one control on this card that is
/// not a model verb — deliberately. It spends nothing, publishes nothing and changes nothing; it
/// asks the same question again. A read that failed with no way to ask again is the dead end
/// `professional-ui` forbids, and routing a retry through the tray would put a *"read my profile
/// again"* row on a menu where it means nothing.
fn unreadable(flow: &mut Flow, t: &Tokens, why: &str) -> Option<TrayAction> {
    let state = PaneState::Unreachable(why.to_string());
    flow.place(|ui, at| (state::banner(ui, at, t, &state), ()));
    flow.gap(space::S3);

    let retry = [Action {
        label: copy::profile_edit::RETRY.to_string(),
        weight: Weight::Ghost,
        enabled: true,
        id: Local::ReadAgain,
        element: retry_element(),
    }];
    let live = flow.live();
    let pressed = flow.place(|ui, at| action::buttons(ui, at, t, live, &retry));
    if pressed == Some(Local::ReadAgain) {
        EditService::app().read_again();
    }
    None
}

/// The form: every field, what is wrong with any of them, and what saving costs.
fn form(
    flow: &mut Flow,
    t: &Tokens,
    committed: &ProfileDraft,
    verbs: &[Action<TrayAction>],
) -> Option<TrayAction> {
    // Loaded inside a zero-height block, because a `Flow` hands out a `Ui` only for the width of
    // one block and the session lives in that `Ui`'s own store.
    let mut session = flow.place(|ui, _| (0.0, session::load(ui, committed)));
    session.collect_a_finished_choice();

    if committed.is_empty() {
        let empty = PaneState::Empty(copy::profile_edit::EMPTY.to_string());
        flow.place(|ui, at| (state::banner(ui, at, t, &empty), ()));
        flow.gap(space::S3);
    }

    // Above the fields, not below them: a person reads the requirement into the form the moment
    // they see it, so the sentence that says there is none has to arrive first.
    flow.place(|ui, at| (text::body(ui, at, t, copy::profile_edit::ALL_OPTIONAL), ()));
    flow.gap(space::S3);
    profile_form::draw_fields(flow, t, &mut session, SCOPE);

    flow.gap(space::S4);
    flow.place(|ui, at| (text::caption(ui, at, t, copy::profile_edit::COST), ()));
    flow.gap(space::S2);
    flow.place(|ui, at| (text::caption(ui, at, t, copy::profile_edit::PUBLIC), ()));
    flow.gap(space::S3);

    let ready = session.draft.is_committable();
    let offered: Vec<Action<TrayAction>> = verbs
        .iter()
        .map(|verb| Action {
            // The label is the model's, verbatim. What this pane decides is only whether the
            // control is pressable right now.
            enabled: verb.enabled && ready,
            ..verb.clone()
        })
        .collect();

    let live = flow.live();
    let pressed = flow.place(|ui, at| action::buttons(ui, at, t, live, &offered));
    if !ready && !session.draft.is_dirty() {
        flow.gap(space::S2);
        flow.place(|ui, at| {
            (
                text::caption(ui, at, t, copy::profile_edit::NOTHING_CHANGED),
                (),
            )
        });
    }

    if pressed.is_some() {
        EditService::app().save(session.draft.changes());
    }
    flow.place(|ui, _| (0.0, session::store(&session, ui)));
    pressed
}

/// A control on this pane that is NOT one of the model's verbs.
///
/// Deliberately a separate type from [`TrayAction`]: this one reaches no worker, spends nothing, and
/// belongs on no menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Local {
    /// Ask for the profile again after a failed read.
    ReadAgain,
}

/// The retry control's element id.
fn retry_element() -> egui::Id {
    egui::Id::new("dig-window-profile-edit-retry")
}

/// The Save verbs the model built for this card, found by the section's shared heading rather than
/// by position — the coupling the merged Account pane exists to avoid.
pub(super) fn save_verbs(tab: &Tab) -> Vec<Action<TrayAction>> {
    let mut seen = std::collections::HashMap::new();
    tab.sections
        .iter()
        .flat_map(|section| {
            let drawn = super::actions_in(section.rows.iter().cloned(), &mut seen);
            match section.heading.as_deref() == Some(crate::window_model::PROFILE_EDIT_HEADING) {
                true => drawn,
                false => Vec::new(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// The form's own state, across frames
// ---------------------------------------------------------------------------------------------

/// What the person has typed, over the profile as it was last read.
///
/// Held in the frame context rather than in the shell, for the Settings pane's reason: the shell
/// knows nothing about these values and a half-typed profile is not application state.
type Session = Form;

/// The id the session is kept under, for the life of the window.
fn session_id() -> egui::Id {
    egui::Id::new("dig-profile-edit-session")
}

/// The element-id namespace this form's inputs live in.
const SCOPE: Scope = Scope("dig-window-profile-edit");

/// Free functions rather than an inherent impl, because the session IS the shared
/// [`Form`] and only the loading RULE below belongs to the editor.
mod session {
    use super::{Form, ProfileDraft, Session, Ui};

    /// This window's session, over the profile as it currently reads.
    ///
    /// # Why a NEWER read does not throw typing away
    ///
    /// The service re-reads while a person is typing, so the committed values underneath can change
    /// mid-form. Rebuilding the draft on every read would delete their work as they did it; keeping
    /// the old one forever would compute the change set against a profile that has moved. So a held
    /// session is kept while it is DIRTY and replaced when it is not: somebody mid-edit keeps every
    /// character, and somebody who has typed nothing gets the fresh values.
    pub(super) fn load(ui: &Ui, committed: &ProfileDraft) -> Session {
        match ui.data(|d| d.get_temp::<Session>(super::session_id())) {
            Some(held) if held.draft.is_dirty() => held,
            _ => Form::over(committed.clone()),
        }
    }

    /// Keep `session` for the next frame.
    pub(super) fn store(session: &Session, ui: &Ui) {
        ui.data_mut(|d| d.insert_temp(super::session_id(), session.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_edit::ProfileField;
    use std::collections::BTreeMap;

    fn a_profile() -> ProfileDraft {
        let mut values = BTreeMap::new();
        values.insert(ProfileField::DisplayName, "Ada".to_string());
        ProfileDraft::over(values, 22)
    }

    /// Typing survives the profile being re-read underneath the form. The service polls while a
    /// person types, and a session rebuilt on every answer deletes their work as they do it.
    #[test]
    fn a_reread_underneath_a_dirty_form_does_not_throw_away_what_was_typed() {
        let ctx = egui::Context::default();
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let mut session = session::load(ui, &a_profile());
                session.draft.set(ProfileField::Bio, "Builds engines.");
                session::store(&session, ui);

                let after = session::load(ui, &a_profile());
                assert_eq!(after.draft.value(ProfileField::Bio), "Builds engines.");
            });
        });
    }

    /// And the other half: a form nobody has touched takes the newest values, so a profile changed
    /// on another machine does not sit stale on this one forever.
    #[test]
    fn a_clean_form_takes_the_newest_committed_values() {
        let ctx = egui::Context::default();
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                session::store(&Form::over(a_profile()), ui);

                let mut moved_on = BTreeMap::new();
                moved_on.insert(ProfileField::DisplayName, "Ada Lovelace".to_string());
                let after = session::load(ui, &ProfileDraft::over(moved_on, 30));
                assert_eq!(after.draft.value(ProfileField::DisplayName), "Ada Lovelace");
            });
        });
    }

    /// **No single field is required, in either direction** (dig_ecosystem#3057).
    ///
    /// The user's report was that every box felt mandatory. The draft model has no required-field
    /// rule, so what this pins is that none can be introduced — by a validator, by a gate written
    /// against a display name, or by an `is_committable` that grew a condition.
    ///
    /// # Why it is asserted per FIELD and in both directions
    ///
    /// One fixture that sets one field would pass on an implementation requiring exactly that
    /// field. So each field is exercised as the ONLY thing filled in, over an empty profile — the
    /// person who wants to publish one detail and nothing else — and then each is exercised as the
    /// only thing REMOVED from a full profile, which is the other half of optional: a box you may
    /// empty again. An implementation that required a field passes neither leg for that field.
    #[test]
    fn every_field_may_be_the_only_one_filled_in_and_the_only_one_emptied() {
        for field in ProfileField::ALL {
            let mut alone = ProfileDraft::empty();
            alone.set(field, an_acceptable_value_for(field));
            assert!(
                alone.is_committable(),
                "{field:?} cannot be published on its own, so some other box is required"
            );

            let mut full = a_filled_profile();
            full.clear(field);
            assert!(
                full.is_committable(),
                "{field:?} cannot be emptied, so it is required once it has been filled in"
            );
        }
    }

    /// A value each field genuinely accepts — the address and image slots are validated, so a single
    /// placeholder string would fail those two for a reason that has nothing to do with this test.
    fn an_acceptable_value_for(field: ProfileField) -> String {
        match field {
            ProfileField::XchAddress => {
                "xch17s7wd45k6vpmpwcqu26x43x5kac6u3n6pprjl9ssal6qp3dlvmjqf4snk5".to_string()
            }
            field if field.is_image() => "data:image/png;base64,iVBORw0KGgo=".to_string(),
            _ => "something".to_string(),
        }
    }

    /// A profile holding an acceptable value in EVERY field, so any one of them can be emptied.
    fn a_filled_profile() -> ProfileDraft {
        let values: BTreeMap<ProfileField, String> = ProfileField::ALL
            .into_iter()
            .map(|field| (field, an_acceptable_value_for(field)))
            .collect();
        let len = values.values().map(|v| v.len() + 11).sum::<usize>() + 5;
        ProfileDraft::over(values, len)
    }

    /// **The form says the boxes are optional before a person reads a requirement into them.**
    ///
    /// The sentence is the only thing standing between a truthful model and a person inventing a
    /// display name because the box looked mandatory.
    #[test]
    fn the_editor_says_every_box_is_optional() {
        let said = copy::profile_edit::ALL_OPTIONAL.to_lowercase();
        assert!(said.contains("optional"), "{said}");
        assert!(
            said.contains("empty"),
            "the sentence never says a box may be left or made empty: {said}"
        );
    }

    /// **And the form actually PAINTS it** (dig_ecosystem#3057).
    ///
    /// The test above is about a string constant: it holds whether or not anything draws that
    /// string, so deleting the `flow.place` that paints it leaves it green. What a person reads is
    /// a property of the rendered form, so this one renders the real form and reads the text it
    /// produced — the shape the profiles card's own `card_says` uses, for the same reason.
    #[test]
    fn the_rendered_form_paints_the_optional_sentence() {
        let painted = form_says(&a_profile());
        assert!(
            painted.contains(copy::profile_edit::ALL_OPTIONAL),
            "the form drew no sentence saying the boxes are optional; it said: {painted}"
        );
    }

    /// Every string the real form painted over `committed`.
    ///
    /// Drawn through the REAL [`form`] and a REAL [`Flow`], because the property under test is what
    /// a person SEES. The card's outer states are not exercised here: reaching them means the
    /// process-wide [`EditService`], and the sentence lives in the form regardless of how the read
    /// that produced `committed` arrived.
    fn form_says(committed: &ProfileDraft) -> String {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let t = crate::confirm::gui::theme::Theme::Light.tokens();
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::Vec2::new(420.0, 8_000.0));

        let mut output = egui::FullOutput::default();
        // Two frames: the first builds the font atlas, the second lays out against it.
        for _ in 0..2 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("profile-edit-form-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            let column = egui::Rect::from_min_size(
                                screen.left_top(),
                                egui::Vec2::new(screen.width() - space::S5 * 2.0, f32::INFINITY),
                            );
                            let mut flow = Flow::new(ui, column, true);
                            super::form(&mut flow, &t, committed, &[]);
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
        said.join(" | ")
    }

    /// Nothing to save is not something to press. The label still says what the control does — the
    /// model wrote it — and this pane only decides that it cannot be pressed right now.
    #[test]
    fn a_clean_form_and_an_oversize_form_both_have_nothing_to_save() {
        let clean = a_profile();
        assert!(!clean.is_committable());

        let mut oversize = a_profile();
        oversize.set(
            ProfileField::Avatar,
            "d".repeat(crate::profile_edit::MAX_SLOT_PAYLOAD + 1),
        );
        assert!(oversize.is_dirty());
        assert!(!oversize.is_committable(), "an oversize draft is pressable");
    }
}
