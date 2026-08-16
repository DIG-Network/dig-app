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

use egui::{Rect, Ui};

use super::action::{self, Action};
use super::card;
use super::copy;
use super::facts::PaneFacts;
use super::field::{self, Field};
use super::flow::Flow;
use super::image_pick::{self, InFlight, PickProblems};
use super::state::{self, PaneState};
use super::text;
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::profile_edit::{
    EditService, ProfileDraft, ProfileEditing, ProfileField, ProfileReading,
};
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
        ProfileReading::Known(committed) => form(flow, t, committed, verbs),
    }
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
    let mut session = flow.place(|ui, _| (0.0, Session::load(ui, committed)));
    session.collect_a_finished_choice();

    if committed.is_empty() {
        let empty = PaneState::Empty(copy::profile_edit::EMPTY.to_string());
        flow.place(|ui, at| (state::banner(ui, at, t, &empty), ()));
        flow.gap(space::S3);
    }

    for (index, edited) in ProfileField::ALL.into_iter().enumerate() {
        if index > 0 {
            flow.gap(space::S3);
        }
        draw_field(flow, t, &mut session, edited);
    }

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
    flow.place(|ui, _| (0.0, session.store(ui)));
    pressed
}

/// One field: its label, its input, and whatever is wrong with it.
fn draw_field(flow: &mut Flow, t: &Tokens, session: &mut Session, edited: ProfileField) {
    let problem = session.shown_problem(edited);
    let live = flow.live();
    let described = Field {
        label: edited.label(),
        placeholder: edited.placeholder(),
        help: edited.help(),
        error: problem,
        id: element(edited),
    };

    // Typed into a local and compared afterwards rather than edited in place: the draft owns both
    // what was committed and what was typed, and handing a `&mut String` into it would make every
    // repaint a write even when nothing was pressed.
    let mut typed = session.draft.value(edited).to_string();
    flow.place(|ui, at| {
        (
            field::text_field(ui, at, t, live, &described, &mut typed),
            (),
        )
    });

    if typed != session.draft.value(edited) {
        session.draft.set(edited, typed);
        // What the person typed is now the value, so a complaint about the FILE they picked before
        // is about something that is no longer there.
        session.picked.remove(&edited);
    }

    if edited.is_image() {
        flow.gap(space::S2);
        image_controls(flow, t, session, edited);
    }
}

/// The two ways a picture gets into an image field: the system's chooser, and a dropped file.
///
/// Both exist deliberately. Drag-and-drop is the faster one and the one nobody discovers on their
/// own; the button is the one that works for a person who cannot drag, on a machine with no pointer,
/// or from a file manager that will not drag onto this window. A drop-only affordance would be the
/// dead end `professional-ui` forbids.
fn image_controls(flow: &mut Flow, t: &Tokens, session: &mut Session, edited: ProfileField) {
    let live = flow.live();
    let choosing = session.is_choosing_for(edited);
    let controls = [Action {
        label: copy::profile_edit::CHOOSE.to_string(),
        weight: Weight::Ghost,
        // One chooser at a time: two open dialogs writing into one form is a race a person cannot
        // see, and the answer that lands second would silently win.
        enabled: live && session.in_flight.is_none(),
        id: Local::Choose(edited),
        element: choose_element(edited),
    }];

    let (pressed, dropped, ctx) = flow.place(|ui, at| {
        let (height, pressed) = action::buttons(ui, at, t, live, &controls);
        let row = Rect::from_min_size(at.min, egui::Vec2::new(at.width(), height));
        (height, (pressed, dropped_onto(ui, row), ui.ctx().clone()))
    });

    flow.gap(space::S1);
    let beside = match choosing {
        true => copy::profile_edit::CHOOSING,
        false => copy::profile_edit::DRAG,
    };
    flow.place(|ui, at| (text::caption(ui, at, t, beside), ()));

    if let Some(path) = dropped {
        image_pick::dropped(&mut session.draft, &mut session.picked, edited, &path);
    }
    if pressed == Some(Local::Choose(edited)) && session.in_flight.is_none() {
        session.in_flight = Some(InFlight::open(edited, ctx));
    }
}

/// The path of a file let go over `row` this frame, if any.
///
/// Routed by where the pointer IS rather than by which field was last touched: the editor has two
/// image fields, and a drop that landed on the wrong one would publish the picture in the wrong
/// place with nothing reporting a fault.
fn dropped_onto(ui: &Ui, row: Rect) -> Option<std::path::PathBuf> {
    ui.ctx().input(|i| {
        let over = i
            .pointer
            .hover_pos()
            .or_else(|| i.pointer.interact_pos())
            .is_some_and(|at| row.contains(at));
        match over {
            // Only the first: several files dropped at once are several pictures for one slot, and
            // choosing quietly among them is a choice the person did not make.
            true => i.raw.dropped_files.iter().find_map(|f| f.path.clone()),
            false => None,
        }
    })
}

/// A control on this pane that is NOT one of the model's verbs.
///
/// Deliberately a separate type from [`TrayAction`]: this one reaches no worker, spends nothing, and
/// belongs on no menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Local {
    /// Ask for the profile again after a failed read.
    ReadAgain,
    /// Open the system's file chooser for an image field.
    Choose(ProfileField),
}

/// The retry control's element id.
fn retry_element() -> egui::Id {
    egui::Id::new("dig-window-profile-edit-retry")
}

/// One image field's chooser-button element id, keyed on the field for the same reason the inputs
/// are: two buttons sharing an id are one button to egui, so pressing either would open the chooser
/// for whichever field drew first.
fn choose_element(edited: ProfileField) -> egui::Id {
    egui::Id::new(("dig-window-profile-edit-choose", edited.slot().id()))
}

/// One field's input element id, keyed on the field so focus and the caret survive the pane being
/// rebuilt every frame.
fn element(edited: ProfileField) -> egui::Id {
    egui::Id::new(("dig-window-profile-edit-field", edited.slot().id()))
}

/// The Save verbs the model built for this card, found by the section's shared heading rather than
/// by position — the coupling the merged Account pane exists to avoid.
fn save_verbs(tab: &Tab) -> Vec<Action<TrayAction>> {
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
#[derive(Clone)]
struct Session {
    /// The draft, which holds both the committed values and everything typed over them.
    draft: ProfileDraft,
    /// Why the last file chosen for a field could not be used, per field.
    ///
    /// Kept beside the draft rather than in it: the draft judges VALUES, and "that file would not
    /// open" is not a fact about the value the field currently holds.
    picked: PickProblems,
    /// The file chooser that is open right now, if one is.
    in_flight: Option<InFlight>,
}

/// The id the session is kept under, for the life of the window.
fn session_id() -> egui::Id {
    egui::Id::new("dig-profile-edit-session")
}

impl Session {
    /// This window's session, over the profile as it currently reads.
    ///
    /// # Why a NEWER read does not throw typing away
    ///
    /// The service re-reads while a person is typing, so the committed values underneath can change
    /// mid-form. Rebuilding the draft on every read would delete their work as they did it; keeping
    /// the old one forever would compute the change set against a profile that has moved. So a held
    /// session is kept while it is DIRTY and replaced when it is not: somebody mid-edit keeps every
    /// character, and somebody who has typed nothing gets the fresh values.
    fn load(ui: &Ui, committed: &ProfileDraft) -> Self {
        match ui.data(|d| d.get_temp::<Self>(session_id())) {
            Some(held) if held.draft.is_dirty() => held,
            _ => Self::over(committed.clone()),
        }
    }

    /// A fresh session over `draft`, with nothing chosen and no chooser open.
    fn over(draft: ProfileDraft) -> Self {
        Self {
            draft,
            picked: PickProblems::new(),
            in_flight: None,
        }
    }

    fn store(&self, ui: &Ui) {
        ui.data_mut(|d| d.insert_temp(session_id(), self.clone()));
    }

    /// Take the answer from a file chooser that has finished, and put it where it belongs.
    fn collect_a_finished_choice(&mut self) {
        let Some(flight) = self.in_flight.clone() else {
            return;
        };
        if let Some(answer) = flight.taken() {
            image_pick::apply(&mut self.draft, &mut self.picked, flight.field, answer);
            self.in_flight = None;
        }
    }

    /// Whether a chooser opened from `edited` is still open.
    fn is_choosing_for(&self, edited: ProfileField) -> bool {
        self.in_flight.as_ref().is_some_and(|f| f.field == edited)
    }

    /// What to say under `edited`: the file it refused, else what is wrong with its value.
    ///
    /// The file comes first because it is the more recent thing the person did, and because a
    /// refused file leaves the previous value in place — so the value's own verdict would be about
    /// a picture they were not asking about.
    fn shown_problem(&self, edited: ProfileField) -> Option<String> {
        self.picked
            .get(&edited)
            .cloned()
            .or_else(|| self.draft.problem(edited))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
                let mut session = Session::load(ui, &a_profile());
                session.draft.set(ProfileField::Bio, "Builds engines.");
                session.store(ui);

                let after = Session::load(ui, &a_profile());
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
                Session::over(a_profile()).store(ui);

                let mut moved_on = BTreeMap::new();
                moved_on.insert(ProfileField::DisplayName, "Ada Lovelace".to_string());
                let after = Session::load(ui, &ProfileDraft::over(moved_on, 30));
                assert_eq!(after.draft.value(ProfileField::DisplayName), "Ada Lovelace");
            });
        });
    }

    /// Each field addresses its own input. Two fields sharing an element id would make egui treat
    /// them as one widget, so typing in either would edit the other.
    #[test]
    fn every_field_has_its_own_input_element() {
        let ids: std::collections::HashSet<egui::Id> =
            ProfileField::ALL.iter().map(|f| element(*f)).collect();
        assert_eq!(ids.len(), ProfileField::ALL.len());
        assert!(!ids.contains(&retry_element()));
    }

    /// Every control on the pane addresses its own element. The two image fields each get a chooser
    /// button, and a shared id would make egui treat them as one widget — so pressing "choose" under
    /// the header would open the chooser for the profile picture.
    #[test]
    fn every_chooser_button_has_its_own_element() {
        let image_fields: Vec<ProfileField> = ProfileField::ALL
            .into_iter()
            .filter(|f| f.is_image())
            .collect();
        assert_eq!(
            image_fields.len(),
            2,
            "the fixture below needs two to compare"
        );

        let ids: std::collections::HashSet<egui::Id> =
            image_fields.iter().map(|f| choose_element(*f)).collect();
        assert_eq!(ids.len(), image_fields.len());
        for field in ProfileField::ALL {
            assert!(!ids.contains(&element(field)));
        }
    }

    /// A file the person picked is complained about UNDER the field they picked it for, and the
    /// other image field is unaffected.
    ///
    /// The control is the second image field carrying a genuinely invalid VALUE: an implementation
    /// that kept one message for the whole form would show the header's file complaint under the
    /// picture too, and one that ignored pick problems entirely would show the value complaint
    /// under the header. Only per-field routing produces both of these answers at once.
    #[test]
    fn a_file_complaint_is_shown_under_the_field_it_was_chosen_for() {
        let mut session = Session::over(a_profile());
        session.draft.set(
            ProfileField::Avatar,
            "d".repeat(crate::profile_edit::MAX_SLOT_PAYLOAD + 1),
        );
        session
            .picked
            .insert(ProfileField::Banner, "wide.png is not an image".to_string());

        assert_eq!(
            session.shown_problem(ProfileField::Banner).as_deref(),
            Some("wide.png is not an image")
        );
        let avatar = session.shown_problem(ProfileField::Avatar);
        assert!(
            avatar.is_some(),
            "the oversize value stopped being reported"
        );
        assert_ne!(avatar.as_deref(), Some("wide.png is not an image"));
        assert_eq!(session.shown_problem(ProfileField::DisplayName), None);
    }

    /// **A dropped file is claimed by the row it was let go over, and by no other row.**
    ///
    /// This is the placement property, and it needs TWO rows to be visible at all: an
    /// implementation that ignored the pointer and simply took `dropped_files` would satisfy "the
    /// row under the pointer got the file" on a one-row fixture, and would hand the same file to
    /// both image fields in the real pane. The second row here is the honest control that catches
    /// it — it must come back empty on the very same frame.
    #[test]
    fn a_drop_is_claimed_only_by_the_row_under_the_pointer() {
        let over_the_header = egui::Pos2::new(20.0, 150.0);
        let mut raw = egui::RawInput {
            dropped_files: vec![egui::DroppedFile {
                path: Some(std::path::PathBuf::from("wide.png")),
                ..Default::default()
            }],
            ..Default::default()
        };
        raw.events.push(egui::Event::PointerMoved(over_the_header));

        let ctx = egui::Context::default();
        let _ = ctx.run(raw, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let picture_row =
                    Rect::from_min_size(egui::Pos2::new(0.0, 0.0), egui::Vec2::new(400.0, 40.0));
                let header_row =
                    Rect::from_min_size(egui::Pos2::new(0.0, 120.0), egui::Vec2::new(400.0, 40.0));

                assert_eq!(
                    dropped_onto(ui, header_row),
                    Some(std::path::PathBuf::from("wide.png")),
                    "the row the file was let go over did not claim it"
                );
                assert_eq!(
                    dropped_onto(ui, picture_row),
                    None,
                    "a file dropped on the header was also taken by the profile picture"
                );
            });
        });
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
