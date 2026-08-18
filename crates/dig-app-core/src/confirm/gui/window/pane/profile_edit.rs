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
                content(inner, t, offer, &verbs, CARD_FORM)
            });
        (height, pressed.flatten())
    })
}

/// The same content, drawn inside the per-profile edit modal (dig_ecosystem#3069, criterion 4).
///
/// Reports whether a SAVE was pressed, which is the modal's cue to close — see
/// [`super::super::profile_modal`]: the write belongs to a worker from that instant, and a modal
/// that stayed up would be the only thing holding an outcome it does not own.
///
/// # Why the modal reuses this rather than drawing its own form
///
/// Every reading state the card handles — a read in flight, a read that failed, a profile that has
/// published nothing, one whose content contradicts the chain — is a state the modal is in too. A
/// second rendering of those five answers is how two surfaces come to disagree about what a person's
/// profile currently is, and the one that is wrong is whichever was edited second.
///
/// The Save CONTROL is the one thing built separately, with an element id of its own: drawing the
/// model's own action in two live surfaces at once would give egui two widgets under one id, which
/// it resolves by silently refusing one of them. The LABEL is still the model's, verbatim.
pub(crate) fn modal_body(flow: &mut Flow, t: &Tokens, offer: ProfileEditing) {
    // No verbs. The Save control is drawn by the modal, PINNED below the scrolling form — a form
    // eight fields long is taller than any modal is allowed to be, and a Save at the bottom of it
    // is a control a person has to go looking for. See `modal_save_offer`.
    content(flow, t, offer, &[], MODAL_FORM);
}

/// What the modal's pinned Save control should say, and whether it may be pressed.
///
/// `None` when there is nothing to save through: the editor is blocked, or the profile has not been
/// read yet, so a control would act on a form that is not on screen.
///
/// # Why the reading is asked about here and not left to the service
///
/// [`EditService::save`] already refuses over a profile this app has not read, so the money was
/// never at risk. What was at risk is the truth: the row is drawn outside the body, so a read that
/// failed under a form somebody had already typed into left Save enabled over a banner — and
/// pressing it published nothing while closing the modal exactly as a real save does. A refusal
/// nobody can see is indistinguishable from success (dig_ecosystem#3069).
///
/// The LABEL is the model's, verbatim — the modal decides only whether it is pressable this frame,
/// which is a fact about what has been typed and lives nowhere but in the form's own session.
pub(crate) fn modal_save_offer(
    ui: &Ui,
    tab: &Tab,
    offer: ProfileEditing,
    reading: &ProfileReading,
) -> Option<(String, bool)> {
    if !offer.is_possible() {
        return None;
    }
    // The two readings [`EditService::save`] will actually act on. Withholding Save over
    // `BodyLost` is what made its form a dead control: the card invited a person to publish and the
    // one row that could do it was not drawn (dig_ecosystem#3041).
    if !matches!(
        reading,
        ProfileReading::Known(_) | ProfileReading::BodyLost { .. }
    ) {
        return None;
    }
    let label = save_verbs(tab).first().map(|verb| verb.label.clone())?;
    let session = ui.data(|d| d.get_temp::<Session>(egui::Id::new(MODAL_FORM.session)))?;
    Some((label, session.draft.is_committable()))
}

/// Hand the modal's typed changes to the service.
///
/// Everything about the write from here on belongs to a worker: the bytes are persisted before the
/// spend by [`EditService::save`] itself (dig_ecosystem#3066), and the transaction modal reports the
/// rest. Nothing is kept here, which is why the modal may close on the very next line.
pub(crate) fn modal_save(ui: &Ui) {
    let Some(session) = ui.data(|d| d.get_temp::<Session>(egui::Id::new(MODAL_FORM.session)))
    else {
        return;
    };
    EditService::app().save(session.draft.changes());
}

/// Drop whatever is half-typed in the modal's form.
///
/// Called when the modal closes, which is what makes the module header's *the typing is dropped*
/// true. A draft that outlived its modal is also what the pinned Save reads to decide there is
/// something to publish, so leaving one behind offers a control over a form nobody has opened.
pub(crate) fn forget_modal_typing(ctx: &egui::Context) {
    ctx.data_mut(|d| d.remove::<Session>(egui::Id::new(MODAL_FORM.session)));
}

/// The card's body: the blocker that explains itself, or the form.
fn content(
    flow: &mut Flow,
    t: &Tokens,
    offer: ProfileEditing,
    verbs: &[Action<TrayAction>],
    form_id: FormId,
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
        ProfileReading::Unreadable(why) => unreadable(flow, t, why, form_id),
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
        // The one unreadable state that still gets the form (dig_ecosystem#3041). The banner goes
        // FIRST and says the content is gone, so the blank fields below it are read as a re-entry
        // rather than as this person's profile — the distinction that stops someone publishing three
        // empty fields believing they are preserving what was there.
        ProfileReading::BodyLost { root, draft } => {
            let lost = PaneState::Unreachable(crate::profile_edit::copy::body_lost(root));
            flow.place(|ui, at| (state::banner(ui, at, t, &lost), ()));
            flow.gap(space::S3);
            form(flow, t, draft, verbs, form_id, reading.is_re_entry())
        }
        ProfileReading::Known(committed) => form(flow, t, committed, verbs, form_id, false),
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
fn unreadable(flow: &mut Flow, t: &Tokens, why: &str, form_id: FormId) -> Option<TrayAction> {
    let state = PaneState::Unreachable(why.to_string());
    flow.place(|ui, at| (state::banner(ui, at, t, &state), ()));
    flow.gap(space::S3);

    let retry = [Action {
        label: copy::profile_edit::RETRY.to_string(),
        weight: Weight::Ghost,
        enabled: true,
        id: Local::ReadAgain,
        element: retry_element(form_id),
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
    form_id: FormId,
    re_entry: bool,
) -> Option<TrayAction> {
    // Loaded inside a zero-height block, because a `Flow` hands out a `Ui` only for the width of
    // one block and the session lives in that `Ui`'s own store.
    let mut session = flow.place(|ui, _| (0.0, session::load(ui, committed, form_id)));
    session.collect_a_finished_choice();

    // Suppressed for a re-entry, and the suppression is the whole point. A `BodyLost` draft is
    // ALWAYS empty, so this drew "Your profile is empty. Nothing has gone wrong" immediately beneath
    // a banner saying the content was destroyed — reinstating, one line lower, the exact reassurance
    // dig_ecosystem#3041 removed. `ProfileReading::is_empty` is correctly false for that state; this
    // consulted the DRAFT's emptiness instead, so the invariant was held at the model and bypassed
    // at the surface. The loss banner is already overhead and says the true version.
    if committed.is_empty() && !re_entry {
        let empty = PaneState::Empty(copy::profile_edit::EMPTY.to_string());
        flow.place(|ui, at| (state::banner(ui, at, t, &empty), ()));
        flow.gap(space::S3);
    }

    // Above the fields, not below them: a person reads the requirement into the form the moment
    // they see it, so the sentence that says there is none has to arrive first.
    flow.place(|ui, at| (text::body(ui, at, t, copy::profile_edit::ALL_OPTIONAL), ()));
    flow.gap(space::S3);
    profile_form::draw_fields(flow, t, &mut session, form_id.scope);

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
    flow.place(|ui, _| (0.0, session::store(&session, ui, form_id)));
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

/// The retry control's element id, per DRAWING of the editor.
///
/// Two live surfaces sharing one id are one widget to egui, which resolves the clash by refusing
/// one of them — a retry button that silently does nothing.
fn retry_element(form: FormId) -> egui::Id {
    egui::Id::new(("dig-window-profile-edit-retry", form.session))
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

/// Which DRAWING of the editor a form belongs to.
///
/// The Account tab's card and the per-profile modal can be alive in the same frame, and to egui two
/// widgets under one id are one widget — so typing in the modal would edit the card's boxes
/// underneath it, invisibly. Both the element namespace and the session slot are carried here so
/// the two cannot be given one and not the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FormId {
    /// The element-id namespace this form's inputs live in.
    scope: Scope,
    /// The key its half-typed state is kept under.
    session: &'static str,
}

/// The Account tab's own card.
const CARD_FORM: FormId = FormId {
    scope: Scope("dig-window-profile-edit"),
    session: "dig-profile-edit-session",
};

/// The per-profile edit modal.
const MODAL_FORM: FormId = FormId {
    scope: Scope("dig-window-profile-modal"),
    session: "dig-profile-modal-session",
};

/// Free functions rather than an inherent impl, because the session IS the shared
/// [`Form`] and only the loading RULE below belongs to the editor.
mod session {
    use super::{Form, FormId, ProfileDraft, Session, Ui};

    /// This window's session, over the profile as it currently reads.
    ///
    /// # Why a NEWER read does not throw typing away
    ///
    /// The service re-reads while a person is typing, so the committed values underneath can change
    /// mid-form. Rebuilding the draft on every read would delete their work as they did it; keeping
    /// the old one forever would compute the change set against a profile that has moved. So a held
    /// session is kept while it is DIRTY and replaced when it is not: somebody mid-edit keeps every
    /// character, and somebody who has typed nothing gets the fresh values.
    pub(super) fn load(ui: &Ui, committed: &ProfileDraft, form: FormId) -> Session {
        match ui.data(|d| d.get_temp::<Session>(egui::Id::new(form.session))) {
            Some(held) if held.draft.is_dirty() => held,
            _ => Form::over(committed.clone()),
        }
    }

    /// Keep `session` for the next frame.
    pub(super) fn store(session: &Session, ui: &Ui, form: FormId) {
        ui.data_mut(|d| d.insert_temp(egui::Id::new(form.session), session.clone()));
    }
}

/// What a test needs to see the modal's half-typed state, without giving production a second way
/// to reach it.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::{Form, ProfileDraft, Session, MODAL_FORM};

    /// Store typing in the modal's session, as a drawn form does.
    pub(crate) fn remember_modal_typing(ui: &egui::Ui) {
        let mut typed = Form::over(ProfileDraft::empty());
        typed
            .draft
            .set(crate::profile_edit::ProfileField::Bio, "Builds engines.");
        super::session::store(&typed, ui, MODAL_FORM);
    }

    /// Whether any typing is still held for the modal's form.
    pub(crate) fn modal_typing_is_held(ctx: &egui::Context) -> bool {
        ctx.data(|d| d.get_temp::<Session>(egui::Id::new(MODAL_FORM.session)))
            .is_some()
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
                let mut session = session::load(ui, &a_profile(), CARD_FORM);
                session.draft.set(ProfileField::Bio, "Builds engines.");
                session::store(&session, ui, CARD_FORM);

                let after = session::load(ui, &a_profile(), CARD_FORM);
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
                session::store(&Form::over(a_profile()), ui, CARD_FORM);

                let mut moved_on = BTreeMap::new();
                moved_on.insert(ProfileField::DisplayName, "Ada Lovelace".to_string());
                let after = session::load(ui, &ProfileDraft::over(moved_on, 30), CARD_FORM);
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

    /// **dig_ecosystem#3041.** The re-entry form does NOT reinstate the reassurance its own banner
    /// just contradicted.
    ///
    /// # The fixture, and why the control is the same draft
    ///
    /// A `BodyLost` draft is ALWAYS empty, and the empty-profile banner is drawn off
    /// `ProfileDraft::is_empty()` — so the form said *"Your profile is empty. Nothing has gone
    /// wrong"* one line below *"This profile's details are not on this computer."* The model was
    /// never wrong:
    /// `ProfileReading::is_empty()` is correctly false for the state. The surface consulted the
    /// draft instead, which is how an invariant defended in one layer is bypassed in the next.
    ///
    /// The control is the SAME empty draft with `re_entry: false`, which is the only thing that
    /// distinguishes this from an implementation that deleted the empty-state banner outright — a
    /// person with a genuinely unfilled profile still needs it, and the fixture would look identical
    /// either way without the second leg.
    ///
    /// It is drawn through the REAL form, because this defect is invisible to every assertion made
    /// about the model and visible in one look at the composed pane.
    #[test]
    fn a_re_entry_form_does_not_tell_a_person_nothing_has_gone_wrong() {
        let nothing_typed = ProfileDraft::over(std::collections::BTreeMap::new(), 0);

        let re_entry = form_says_with(&nothing_typed, true);
        assert!(
            !re_entry.contains("Nothing has gone wrong"),
            "the re-entry form reassured a person whose content was destroyed, directly beneath              the banner saying it was: {re_entry}"
        );
        assert!(
            !re_entry.contains("Your profile is empty"),
            "the re-entry form drew the blank fields as an unfilled profile: {re_entry}"
        );

        // The control: an ordinarily empty profile still gets the banner, so the fix suppressed a
        // sentence in one state rather than deleting it from the form.
        let unfilled = form_says_with(&nothing_typed, false);
        assert!(
            unfilled.contains("Your profile is empty") && unfilled.contains("Nothing has gone wrong"),
            "a person who simply has not filled their profile in lost the sentence that says so:              {unfilled}"
        );

        // And the form is genuinely a form in both, so neither leg passes by drawing nothing.
        for said in [&re_entry, &unfilled] {
            assert!(
                said.contains(copy::profile_edit::ALL_OPTIONAL),
                "no form was painted at all, so the assertions above are about a blank card: {said}"
            );
        }
    }

    /// Every string the real form painted over `committed`.
    ///
    /// Drawn through the REAL [`form`] and a REAL [`Flow`], because the property under test is what
    /// a person SEES. The card's outer states are not exercised here: reaching them means the
    /// process-wide [`EditService`], and the sentence lives in the form regardless of how the read
    /// that produced `committed` arrived.
    fn form_says(committed: &ProfileDraft) -> String {
        form_says_with(committed, false)
    }

    /// The same, over a form drawn as a RE-ENTRY over content that is gone.
    fn form_says_with(committed: &ProfileDraft, re_entry: bool) -> String {
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
                            super::form(&mut flow, &t, committed, &[], CARD_FORM, re_entry);
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

    /// **The pinned Save is offered only over a profile this app has actually READ**
    /// (dig_ecosystem#3069).
    ///
    /// # The sequence this closes
    ///
    /// The modal opens over a `Known` reading, a person types, and the session is stored. Fifteen
    /// seconds later the poll answers `Unreadable` — a node hiccup, or the wallet rate limiter — so
    /// the body draws the banner instead of the form. The pinned row is drawn outside everything the
    /// body decides, so it went on finding that stale session and drawing Save enabled over a body
    /// that was not a form. Pressing it published NOTHING, because [`EditService::save`] correctly
    /// refuses over an unread profile, and the modal closed exactly as it does on a real save.
    ///
    /// # Why both legs are asserted, and why the same session is used for all five
    ///
    /// The refusal leg alone passes against an implementation that never offers Save at all, which
    /// is a control a person can no longer reach. So the `Known` leg is the control, and the four
    /// other states are run over the SAME stored session — the only difference between the fixtures
    /// is the reading, which is the property under test.
    #[test]
    fn the_modal_offers_save_only_over_a_profile_that_has_been_read() {
        let (label, ready) = offer_over(&ProfileReading::Known(a_profile())).expect(
            "a read profile with typing in it offered no Save, so nothing can be published",
        );
        assert_eq!(label, crate::tray_menu::PUBLISH_PROFILE_LABEL);
        assert!(ready, "a dirty, valid form was not pressable");

        // **dig_ecosystem#3041.** Added to THIS test rather than asserted beside it, because the
        // omission was the defect: the sweep below listed every non-`Known` reading and `BodyLost`
        // was simply not among them, so a suite of 1932 tests could not see that its form had no
        // Save row at all. A separate test would have left this list free to go stale again.
        let (lost_label, lost_ready) = offer_over(&ProfileReading::body_lost(&"aa".repeat(32)))
            .expect(
                "a profile whose content is unrecoverable offered no Save, so the form inviting a                  person to publish fresh details is a control that cannot be pressed",
            );
        assert_eq!(lost_label, crate::tray_menu::PUBLISH_PROFILE_LABEL);
        assert!(
            lost_ready,
            "the re-entry form was typed into and still not pressable"
        );

        for unread in [
            ProfileReading::Pending,
            ProfileReading::Unreadable("no node".to_string()),
            ProfileReading::Unpublished,
            ProfileReading::Inconsistent,
        ] {
            assert!(
                offer_over(&unread).is_none(),
                "Save was offered over {unread:?}: pressing it publishes nothing and closes the \
                 modal as if it had saved"
            );
        }
    }

    /// The pinned row's offer over `reading`, with a dirty modal session already stored — the state
    /// a person is in after typing into the form and the read failing underneath them.
    fn offer_over(reading: &ProfileReading) -> Option<(String, bool)> {
        let ctx = egui::Context::default();
        let mut answer = None;
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let mut typed = Form::over(a_profile());
                typed.draft.set(ProfileField::Bio, "Builds engines.");
                session::store(&typed, ui, MODAL_FORM);
                answer = modal_save_offer(ui, &a_tab_offering_save(), editable(), reading);
            });
        });
        answer
    }

    /// The tab the model builds when editing is possible: one Save verb, under the editor's heading.
    fn a_tab_offering_save() -> Tab {
        use crate::window_model::{PaneNote, Section, TabId, PROFILE_EDIT_HEADING};
        Tab {
            id: TabId::Account,
            label: "Account".to_string(),
            note: PaneNote::Ready,
            sections: vec![Section {
                heading: Some(PROFILE_EDIT_HEADING.to_string()),
                rows: vec![crate::tray_menu::MenuRow::Action {
                    action: TrayAction::PublishProfileEdits,
                    label: crate::tray_menu::PUBLISH_PROFILE_LABEL.to_string(),
                    enabled: true,
                }],
            }],
        }
    }

    /// The offer over seams that exist, an unlocked account and a profile — read off the capability
    /// rather than asserted, so this fixture cannot claim one the model would not build.
    fn editable() -> ProfileEditing {
        use crate::profile_edit::commit::{tests_support::NeverSeam, EditSeams};
        let seams = EditSeams::Wired {
            seam: std::sync::Arc::new(NeverSeam),
            bodies: std::sync::Arc::new(crate::profile_edit::commit::tests_support::NeverBodies),
            pending: std::sync::Arc::new(
                crate::profile_edit::pending::doubles::InMemoryPending::default(),
            ),
        };
        ProfileEditing::of_seams(&seams, true, true)
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
