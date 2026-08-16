//! The profile FORM: the fields a person fills in, wherever they are being filled in.
//!
//! # Why the editor and the creation wizard draw the same thing
//!
//! A profile's content is the same content whether it is being created or changed, so the form is
//! written once and drawn twice (dig_ecosystem#3038). The alternative — a second set of inputs for
//! the wizard — is how the two surfaces come to disagree about which field is an image, what is
//! wrong with a value, or where a value is stored, and this epic has already paid once for a second
//! field-to-slot table.
//!
//! What differs between the two is not the form: it is what the values MEAN afterwards. The editor
//! commits changes against a profile that exists; the wizard seeds one that does not. So this module
//! owns the drawing and the file-chooser plumbing, and decides no verb.
//!
//! # Element ids are scoped
//!
//! Two forms alive in one window would share every input's id, and to egui two widgets with one id
//! are one widget — typing in either would edit the other. Every id here is derived from a
//! [`Scope`] the caller names, so the editor's "About you" and the wizard's are separate boxes.

use egui::{Rect, Ui};

use super::action::{self, Action};
use super::copy;
use super::field::{self, Field};
use super::flow::Flow;
use super::image_pick::{self, InFlight, PickProblems};
use super::text;
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::profile_edit::{ProfileDraft, ProfileField};

/// The element-id namespace one drawing of the form lives in.
///
/// A newtype rather than a bare `&str` so a caller cannot pass the label it happens to have to
/// hand; the namespace is a decision about identity, not a piece of copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Scope(pub(crate) &'static str);

/// One form's live state: what is typed, what a chosen file was refused for, and whether a file
/// chooser is open.
#[derive(Clone)]
pub(crate) struct Form {
    /// The draft, which holds both the committed values and everything typed over them.
    pub(crate) draft: ProfileDraft,
    /// Why the last file chosen for a field could not be used, per field.
    ///
    /// Kept beside the draft rather than in it: the draft judges VALUES, and "that file would not
    /// open" is not a fact about the value the field currently holds.
    picked: PickProblems,
    /// The file chooser that is open right now, if one is.
    in_flight: Option<InFlight>,
}

impl Form {
    /// A fresh form over `draft`, with nothing chosen and no chooser open.
    pub(crate) fn over(draft: ProfileDraft) -> Self {
        Self {
            draft,
            picked: PickProblems::new(),
            in_flight: None,
        }
    }

    /// Take the answer from a file chooser that has finished, and put it where it belongs.
    pub(crate) fn collect_a_finished_choice(&mut self) {
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
    pub(crate) fn shown_problem(&self, edited: ProfileField) -> Option<String> {
        self.picked
            .get(&edited)
            .cloned()
            .or_else(|| self.draft.problem(edited))
    }
}

/// Draw every field of the profile, in the order a person thinks about themselves.
pub(crate) fn draw_fields(flow: &mut Flow, t: &Tokens, form: &mut Form, scope: Scope) {
    for (index, edited) in ProfileField::ALL.into_iter().enumerate() {
        if index > 0 {
            flow.gap(space::S3);
        }
        draw_field(flow, t, form, edited, scope);
    }
}

/// One field: its label, its input, and whatever is wrong with it.
fn draw_field(flow: &mut Flow, t: &Tokens, form: &mut Form, edited: ProfileField, scope: Scope) {
    let problem = form.shown_problem(edited);
    let live = flow.live();
    let described = Field {
        label: edited.label(),
        placeholder: edited.placeholder(),
        help: edited.help(),
        error: problem,
        id: element(scope, edited),
    };

    // Typed into a local and compared afterwards rather than edited in place: the draft owns both
    // what was committed and what was typed, and handing a `&mut String` into it would make every
    // repaint a write even when nothing was pressed.
    let mut typed = form.draft.value(edited).to_string();
    flow.place(|ui, at| {
        (
            field::text_field(ui, at, t, live, &described, &mut typed),
            (),
        )
    });

    if typed != form.draft.value(edited) {
        form.draft.set(edited, typed);
        // What the person typed is now the value, so a complaint about the FILE they picked before
        // is about something that is no longer there.
        form.picked.remove(&edited);
    }

    if edited.is_image() {
        flow.gap(space::S2);
        image_controls(flow, t, form, edited, scope);
    }
}

/// The two ways a picture gets into an image field: the system's chooser, and a dropped file.
///
/// Both exist deliberately. Drag-and-drop is the faster one and the one nobody discovers on their
/// own; the button is the one that works for a person who cannot drag, on a machine with no pointer,
/// or from a file manager that will not drag onto this window. A drop-only affordance would be the
/// dead end `professional-ui` forbids.
fn image_controls(
    flow: &mut Flow,
    t: &Tokens,
    form: &mut Form,
    edited: ProfileField,
    scope: Scope,
) {
    let live = flow.live();
    let choosing = form.is_choosing_for(edited);
    let controls = [Action {
        label: copy::profile_edit::CHOOSE.to_string(),
        weight: Weight::Ghost,
        // One chooser at a time: two open dialogs writing into one form is a race a person cannot
        // see, and the answer that lands second would silently win.
        enabled: live && form.in_flight.is_none(),
        id: Chose(edited),
        element: choose_element(scope, edited),
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
        image_pick::dropped(&mut form.draft, &mut form.picked, edited, &path);
    }
    if pressed == Some(Chose(edited)) && form.in_flight.is_none() {
        form.in_flight = Some(InFlight::open(edited, ctx));
    }
}

/// The path of a file let go over `row` this frame, if any.
///
/// Routed by where the pointer IS rather than by which field was last touched: the form has two
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

/// A press of one field's chooser button.
///
/// Deliberately its own type rather than a [`crate::tray_menu::TrayAction`]: it reaches no worker,
/// spends nothing, and belongs on no menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Chose(ProfileField);

/// One image field's chooser-button element id, keyed on the field for the same reason the inputs
/// are: two buttons sharing an id are one button to egui, so pressing either would open the chooser
/// for whichever field drew first.
fn choose_element(scope: Scope, edited: ProfileField) -> egui::Id {
    egui::Id::new((scope.0, "choose", edited.slot().id()))
}

/// One field's input element id, keyed on the field so focus and the caret survive the pane being
/// rebuilt every frame, and on the scope so two forms in one window are two forms.
pub(crate) fn element(scope: Scope, edited: ProfileField) -> egui::Id {
    egui::Id::new((scope.0, "field", edited.slot().id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashSet};

    /// A form over a profile that already holds a name.
    fn a_profile() -> ProfileDraft {
        let mut values = BTreeMap::new();
        values.insert(ProfileField::DisplayName, "Ada".to_string());
        ProfileDraft::over(values, 22)
    }

    /// Each field addresses its own input. Two fields sharing an element id would make egui treat
    /// them as one widget, so typing in either would edit the other.
    #[test]
    fn every_field_has_its_own_input_element() {
        let scope = Scope("a-form");
        let ids: HashSet<egui::Id> = ProfileField::ALL
            .into_iter()
            .map(|field| element(scope, field))
            .collect();

        assert_eq!(ids.len(), ProfileField::ALL.len());
    }

    /// And two FORMS are two forms. The editor and the creation wizard can be alive in one window,
    /// and sharing ids would make a person typing their new profile's name edit their existing
    /// profile's name box instead — invisibly, because both are drawn from their own drafts.
    #[test]
    fn two_scopes_of_the_same_field_are_two_different_elements() {
        for field in ProfileField::ALL {
            assert_ne!(
                element(Scope("editor"), field),
                element(Scope("wizard"), field),
                "{field:?} is the same element in both forms"
            );
            assert_ne!(
                choose_element(Scope("editor"), field),
                choose_element(Scope("wizard"), field)
            );
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
        let mut session = Form::over(a_profile());
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

}
