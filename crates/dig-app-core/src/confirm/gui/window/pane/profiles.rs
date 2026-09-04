//! The Account tab's **profiles** card: which identities this account holds, which one is in use,
//! which are hidden here, and why a new one cannot be created yet (dig_ecosystem#2403).
//!
//! # The state this card is designed around
//!
//! **An empty list, on an account that works perfectly.** Nothing in this build can mint a profile,
//! so every real user reads `Known(vec![])` — and an empty list under a heading, on a tab whose next
//! card is about protecting the account, reads as a fault. It is not one, and the empty state's job
//! is to say all three things at once: what a profile is, that the account already receives money
//! and reads content without one, and that there is no create button because creating one is not
//! available in this version rather than because something failed.
//!
//! # What this card decides, and what it does not
//!
//! It decides the LAYOUT: which rows exist, in what order, with which badges. It decides no verb.
//! The two per-profile verbs arrive already built from [`crate::tray_menu::profile_actions`], and
//! this module matches each to its row by the index in the action's payload — the same device the
//! Content tab uses to find which cache preset is in force. Matching by label would re-sort itself
//! the first time a row was reworded.
//!
//! # The one thing the copy may never imply
//!
//! That deleting takes back what a profile already published. Deleting is real now
//! (dig_ecosystem#3037) — it melts both singletons, so the DID stops resolving and the store's
//! lineage ends — but peers hold profile bodies keyed on `(store_id, root)`, and nothing on chain
//! reaches a copy somebody already has.
//!
//! The rule this replaces was *the copy may never imply a profile can be deleted*, which was correct
//! while hiding was all there was and became false the moment a melt shipped. What survives it is
//! the half that is still true: **hiding is not deleting**, and the hide copy must keep saying so
//! now that a control one row away really does end the profile.

use super::super::profile_modal::Editing;
use super::action::{self, Action};
use super::card;
use super::copy;
use super::data::{self, Tone, Value};
use super::facts::PaneFacts;
use super::flow::Flow;
use super::identity;
use super::profile_form::{self, Form, Scope};
use super::state::{self, PaneState};
use super::text;
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::profile_edit::{seed, ProfileDraft, ProfileSeedRequest};
use crate::profiles::{ProfileCreation, ProfileRow, ProfilesReading, RootReading};
use crate::tray_menu::TrayAction;
use crate::window_model::Tab;

/// Draw the profiles card into `flow`, and report the verb pressed.
pub(crate) fn card(
    flow: &mut Flow,
    t: &Tokens,
    tab: &Tab,
    facts: &PaneFacts,
) -> Option<TrayAction> {
    let verbs = ProfileVerbs::of(tab);
    let reading = facts.profiles.clone();
    let creation = facts.profile_creation;
    let live = flow.live();

    flow.place(|ui, at| {
        let (height, pressed) =
            card::interactive_card(ui, at, t, live, Some(copy::profiles::CARD), |inner| {
                let mut hit = list(inner, t, &reading, &verbs);
                inner.gap(space::S4);
                hit = hit.or(create_panel(inner, t, creation, &reading, &verbs));
                if !verbs.about.is_empty() {
                    inner.gap(space::S3);
                    hit = hit
                        .or(inner.place(|ui, at| action::buttons(ui, at, t, live, &verbs.about)));
                }
                hit
            });
        (height, pressed.flatten())
    })
}

/// The list itself, or the state that explains why there is none.
///
/// The reading is matched EXHAUSTIVELY rather than reduced to an `Option<&[_]>`, because its three
/// states are three different sentences and the middle one — a node-less, faultless, empty answer —
/// is the one every real account gives.
fn list(
    flow: &mut Flow,
    t: &Tokens,
    reading: &ProfilesReading,
    verbs: &ProfileVerbs,
) -> Option<TrayAction> {
    let rows = match reading {
        ProfilesReading::Known(rows) if !rows.is_empty() => rows,
        // The card's own state, drawn inside it. `Empty` and `Waiting` share the recessed panel and
        // only `Unknown` gets amber, because painting an ordinary empty account in warning colours
        // is how a person learns that amber means nothing.
        other => {
            let state = unread(other);
            flow.place(|ui, at| (state::banner(ui, at, t, &state), ()));
            return None;
        }
    };

    // ONE profile at a time, browsed with Previous and Next (dig_ecosystem#3069, criterion 1). A
    // person with four identities was reading four stacked cards each carrying two 64-character
    // ids; the pager is what makes each one readable without making any of them unreachable.
    let showing = showing_page(flow, rows);
    let mut pressed = pager(flow, t, rows, showing);
    flow.gap(space::S3);
    pressed = pressed.or(profile_row(flow, t, &rows[showing], verbs));

    flow.gap(space::S3);
    // What is said under the list depends on whether there is anything to switch BETWEEN, and both
    // arms exist for the same reason: a sentence about an act a person cannot perform is noise, and
    // silence where they might perform one reads as an app that cannot.
    if !rows.iter().any(|profile| !profile.active) {
        // The lone-profile account is the one state with no per-profile control anywhere on the
        // card — nothing to switch to, and the profile in use cannot be hidden — so left silent it
        // reads as an app with no multi-profile support, which is the conclusion a real user
        // reached (dig_ecosystem#3057).
        flow.place(|ui, at| (text::caption(ui, at, t, copy::profiles::ONE_PROFILE), ()));
    } else {
        // The caution sits under the whole list rather than beside each switch control: it is one
        // statement about what switching costs, and repeated per row it would be four paragraphs
        // saying one thing.
        flow.place(|ui, at| (text::caption(ui, at, t, copy::profiles::SWITCH_CAUTION), ()));
        flow.gap(space::S2);
        flow.place(|ui, at| (text::caption(ui, at, t, copy::profiles::HIDE_NOTE), ()));
        flow.gap(space::S2);
        flow.place(|ui, at| {
            (
                text::caption(ui, at, t, copy::profiles::ACTIVE_CANNOT_HIDE),
                (),
            )
        });
    }
    pressed
}

// ---------------------------------------------------------------------------------------------
// The pager
// ---------------------------------------------------------------------------------------------

/// Which row of `rows` is showing, as an index INTO THAT LIST.
///
/// # What is remembered is the `ProfileIx`, never the ordinal
///
/// The list can change under a person: a profile is deleted, another is created, the registry is
/// re-read. An ordinal survives all of those and names a DIFFERENT profile afterwards — with a
/// Delete control on it, under the same page number, with nothing on screen having appeared to
/// change. So the identity is remembered and the ordinal is recomputed from it, and a profile that
/// has genuinely gone falls back to the first page rather than to whoever inherited its position.
fn showing_page(flow: &mut Flow, rows: &[ProfileRow]) -> usize {
    flow.place(|ui, _| {
        let remembered = ui.data(|d| d.get_temp::<u32>(pager_id()));
        let found = remembered
            .and_then(|ix| rows.iter().position(|row| row.ix.0 == ix))
            .unwrap_or(0);
        (0.0, found)
    })
}

/// Remember that `profile` is the one being shown.
fn remember_page(flow: &mut Flow, profile: &ProfileRow) {
    let ix = profile.ix.0;
    flow.place(|ui, _| (0.0, ui.data_mut(|d| d.insert_temp(pager_id(), ix))));
}

/// The id the browsed profile's index is kept under, for the life of the window.
fn pager_id() -> egui::Id {
    egui::Id::new("dig-window-profiles-page")
}

/// The pager's own row: where the person is, and the two ways to move.
///
/// Drawn even for a single profile, so the card never silently changes shape as an account gains a
/// second identity — but with both controls disabled, because there is nowhere to go. The position
/// line says *Profile 1 of 1*, which is the honest reading and the answer to the report that the
/// app looked like it supported only one (dig_ecosystem#3057).
fn pager(flow: &mut Flow, t: &Tokens, rows: &[ProfileRow], showing: usize) -> Option<TrayAction> {
    let live = flow.live();
    let position = format!("Profile {} of {}", showing + 1, rows.len());
    let controls = [
        Action {
            label: copy::profiles::PREVIOUS.to_string(),
            weight: Weight::Ghost,
            enabled: live && showing > 0,
            id: Step::Back,
            element: egui::Id::new("dig-window-profiles-previous"),
        },
        Action {
            label: copy::profiles::NEXT.to_string(),
            weight: Weight::Ghost,
            enabled: live && showing + 1 < rows.len(),
            id: Step::Forward,
            element: egui::Id::new("dig-window-profiles-next"),
        },
    ];

    flow.place(|ui, at| (text::caption(ui, at, t, &position), ()));
    flow.gap(space::S2);
    let stepped = flow.place(|ui, at| action::buttons(ui, at, t, live, &controls));

    // Clamped rather than wrapped: a Next that jumped to the first profile would move a person
    // somewhere they did not ask to go, and both controls already refuse at the ends.
    let moved = match stepped {
        Some(Step::Back) => showing.checked_sub(1),
        Some(Step::Forward) => Some((showing + 1).min(rows.len() - 1)),
        None => None,
    };
    if let Some(landed) = moved {
        remember_page(flow, &rows[landed]);
    }
    None
}

/// A press of one of the pager's controls.
///
/// Its own type rather than a [`TrayAction`]: moving between pages reaches no worker, spends
/// nothing and belongs on no menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Show the profile before this one.
    Back,
    /// Show the profile after it.
    Forward,
}

/// The state to draw for a reading that produced no list.
///
/// `Known(non-empty)` cannot reach here — it has rows to draw — and `Known(empty)` is deliberately
/// [`PaneState::Empty`] rather than an error: the registry answered, and its answer is that this
/// account holds no profile. That is the state of every account in this build.
fn unread(reading: &ProfilesReading) -> PaneState {
    match reading {
        ProfilesReading::Pending => PaneState::Waiting(copy::profiles::PENDING.to_string()),
        ProfilesReading::Unknown(crate::profiles::ProfilesUnknown::Unreadable(why)) => {
            PaneState::Unreachable(copy::profiles::unreadable(why))
        }
        ProfilesReading::Known(_) => PaneState::Empty(copy::profiles::EMPTY.to_string()),
    }
}

/// One profile: its name and badges, the two ids that constitute it, and its verbs.
///
/// # Why both ids, and why in full
///
/// A profile is a DID singleton **and** a dig-store: the DID is who it is, the store is where its
/// content lives, and a card naming only the first describes half of the thing. They are drawn as
/// adjacent rows for that reason — the store belongs to the identity above it, not to the card.
///
/// Both are shown in FULL, wrapped, in the identifier face beside a copy control — the same
/// treatment the DIG ID gets one card up, and for the same reason: nobody transcribes a
/// `did:chia:…` string or a 32-byte launcher id, and truncating either hides characters the reader
/// has no other way to reach.
fn profile_row(
    flow: &mut Flow,
    t: &Tokens,
    profile: &ProfileRow,
    verbs: &ProfileVerbs,
) -> Option<TrayAction> {
    let name = profile.display_name();
    let badges = badges_of(profile);
    let did = profile.did.clone();
    let element = did_element(profile);
    let store = profile.store_id.clone();
    let store_slot = store_element(profile);
    let root = root_value(&profile.root);
    let root_slot = root_element(profile);
    let actions = verbs.for_profile(profile);
    let opened = Editing {
        ix: profile.ix.0,
        name: name.clone(),
        active: profile.active,
    };
    let live = flow.live();

    flow.place(|ui, at| {
        let (height, hit) = card::interactive_card(ui, at, t, live, None, |inner| {
            inner.place(|ui, at| (text::heading(ui, at, t, &name), ()));
            if !badges.is_empty() {
                inner.gap(space::S2);
                inner.place(|ui, at| (badge_row(ui, at, t, &badges), ()));
            }
            inner.gap(space::S3);
            inner.place(|ui, at| {
                (
                    identity::copyable(
                        ui,
                        at,
                        t,
                        copy::profiles::DID_LABEL,
                        &Value::Identifier(did.clone()),
                        element,
                        live,
                    ),
                    (),
                )
            });
            // The store rides directly under the DID because they are the two halves of ONE
            // profile: the DID is who it is, the store is where its content lives. Separating them
            // with anything would invite reading the store as a property of the row rather than of
            // the identity above it.
            inner.gap(space::S2);
            inner.place(|ui, at| {
                (
                    identity::copyable(
                        ui,
                        at,
                        t,
                        copy::profiles::STORE_LABEL,
                        &Value::Identifier(store.clone()),
                        store_slot,
                        live,
                    ),
                    (),
                )
            });
            // The root rides under the store for the same reason the store rides under the DID, and
            // it comes THIRD because it is the value that moves: the two above it name the profile
            // for life, this one names what it currently publishes.
            inner.gap(space::S2);
            inner.place(|ui, at| {
                (
                    identity::copyable(
                        ui,
                        at,
                        t,
                        copy::profiles::ROOT_LABEL,
                        &root,
                        root_slot,
                        live,
                    ),
                    (),
                )
            });
            // The Edit control comes FIRST and is drawn for every profile — the verb a person
            // reaches for most, and the one the redesign is about (criterion 4). It is built here
            // rather than taken from the model because it reaches no worker and spends nothing: it
            // opens a modal, and the modal is what may later spend.
            inner.gap(space::S3);
            let edit = [Action {
                label: copy::profiles::edit(&name),
                weight: Weight::Ghost,
                enabled: live,
                id: (),
                element: edit_element(&opened),
            }];
            if inner
                .place(|ui, at| action::buttons(ui, at, t, live, &edit))
                .is_some()
            {
                inner.place(|ui, _| (0.0, EditRequest::record(ui.ctx(), opened.clone())));
            }

            if actions.is_empty() {
                return None;
            }
            inner.gap(space::S2);
            inner.place(|ui, at| action::buttons(ui, at, t, live, &actions))
        });
        (height, hit.flatten())
    })
}

/// A request from this card that the shell open the edit modal.
///
/// # Why it travels through the frame context
///
/// A modal covers the whole window and owns Escape while it is up; a pane drawn INSIDE the shell
/// can do neither. So the card records what was asked and the shell honours it on the same frame —
/// the device [`super::settings::appearance::Exchange`] already uses to hand the shell a theme.
pub(crate) struct EditRequest;

impl EditRequest {
    /// Record that the person asked to edit `profile`.
    pub(crate) fn record(ctx: &egui::Context, profile: Editing) {
        ctx.data_mut(|d| d.insert_temp(Self::slot(), profile));
    }

    /// Take whatever was recorded, leaving nothing behind.
    ///
    /// Taken rather than read, so one press opens the modal once. A request left in place would
    /// reopen it on the frame after it was closed, which is a modal a person cannot get out of.
    pub(crate) fn take(ctx: &egui::Context) -> Option<Editing> {
        ctx.data_mut(|d| d.remove_temp::<Editing>(Self::slot()))
    }

    /// Where the request is kept.
    fn slot() -> egui::Id {
        egui::Id::new("dig-window-profile-edit-request")
    }
}

/// One profile's Edit-control element id, keyed on its INDEX for [`did_element`]'s reason.
fn edit_element(profile: &Editing) -> egui::Id {
    egui::Id::new(("dig-window-profile-edit-open", profile.ix))
}

/// A profile's badges, drawn left to right on one line. Returns the height used.
fn badge_row(ui: &mut egui::Ui, at: egui::Rect, t: &Tokens, badges: &[(&str, Tone)]) -> f32 {
    let mut x = at.left();
    let mut height: f32 = 0.0;
    for (word, tone) in badges {
        let drawn = data::badge(ui, egui::Pos2::new(x, at.top()), t, word, *tone);
        x = drawn.right() + space::S2;
        height = height.max(drawn.height());
    }
    height
}

/// Which badges a profile carries.
///
/// Two independent facts, so both can be true at once — and one of them cannot: dig-account refuses
/// to hide the ACTIVE profile, so `In use` and `Hidden here` never appear together. Written as two
/// independent tests rather than as a three-way match anyway, because the exclusion is dig-account's
/// invariant and this card's job is to render what it is given, not to re-assert it.
fn badges_of(profile: &ProfileRow) -> Vec<(&'static str, Tone)> {
    let mut badges = Vec::new();
    if profile.active {
        badges.push((copy::profiles::ACTIVE_BADGE, Tone::Good));
    }
    if profile.hidden {
        // Neutral, not `Warn`: a hidden profile is a preference the user expressed, working exactly
        // as they asked. Amber would report their own setting back to them as a problem.
        badges.push((copy::profiles::HIDDEN_BADGE, Tone::Neutral));
    }
    badges
}

/// The element id of a profile's DID copy control.
///
/// Keyed on the profile's INDEX, not on its position in the list: hiding a profile does not move it
/// here, but a future filter would, and an id that moved with the layout is the generated-id hazard
/// dig_ecosystem#2074 records.
fn did_element(profile: &ProfileRow) -> egui::Id {
    egui::Id::new(("dig-window-copy-profile-did", profile.ix.0))
}

/// The element id of a profile's store-id copy control.
///
/// Its own namespace, not [`did_element`]'s: two copy controls in one row sharing an id would make
/// egui treat them as one widget, and pressing either would report the other's value copied.
fn store_element(profile: &ProfileRow) -> egui::Id {
    egui::Id::new(("dig-window-copy-profile-store", profile.ix.0))
}

/// What the root row SHOWS for `reading`.
///
/// # Why an unread root is a sentence and not an empty identifier
///
/// Three of the four states have no hash to draw, and each of them means something different to the
/// person reading it — nobody asked yet, nothing was ever published, the read failed and here is
/// why. [`Value::Unknown`] is the one shape that carries the reason and suppresses the Copy control
/// beside it, so a state with nothing to copy offers nothing to copy.
///
/// A blank or a zero-filled hash would be the wrong answer in every one of them: at a glance it is
/// indistinguishable from a real root, and a root is precisely the value a person lifts off the
/// screen to check somewhere else.
fn root_value(reading: &RootReading) -> Value {
    match reading {
        RootReading::Anchored(root) => Value::Identifier(root.clone()),
        RootReading::Pending => Value::Unknown(copy::profiles::ROOT_PENDING.to_string()),
        RootReading::Unpublished => Value::Unknown(copy::profiles::ROOT_UNPUBLISHED.to_string()),
        // The deciding layer's own words. Flattening them into one house sentence is the defect
        // `ProfileReading::of_read_failure` exists to prevent, and it would be re-committed here.
        RootReading::Unreadable(why) => Value::Unknown(why.clone()),
    }
}

/// The element id of a profile's root copy control.
///
/// A third namespace, for [`store_element`]'s reason: three copy controls sit in one row, and two
/// sharing an id would make egui refuse one of them and report the other's value copied.
fn root_element(profile: &ProfileRow) -> egui::Id {
    egui::Id::new(("dig-window-copy-profile-root", profile.ix.0))
}

/// The model's profile rows, sorted by what each one IS.
///
/// Matched on the ACTION and its payload, never on the label: the labels carry the profile's own
/// name, which the user can change, and a partition that read the words would re-sort itself the
/// moment one was renamed.
struct ProfileVerbs {
    /// The per-profile verbs, in the model's order, with their element ids intact.
    per_profile: Vec<Action<TrayAction>>,
    /// The explainer, which is about the CONCEPT rather than about any one profile — so it is drawn
    /// at the foot of the card, away from the rows, where it cannot be mistaken for a control that
    /// acts on one of them.
    about: Vec<Action<TrayAction>>,
    /// The create control, drawn INSIDE the create panel so the sentence explaining what creating a
    /// profile costs and does is the thing it sits under.
    ///
    /// Empty in every state but [`ProfileCreation::Possible`], because that is the only state in
    /// which the model builds the row at all — the offer is withheld by the MODEL, and this pane
    /// draws what it is given (dig_ecosystem#2939).
    create: Vec<Action<TrayAction>>,
}

impl ProfileVerbs {
    /// Sort the profile section's rows, keeping the model's order and its element ids.
    ///
    /// Ids are assigned over the WHOLE tab before the narrowing, for the reason
    /// [`super::account::protection_actions`] records: the occurrence count is a position in the
    /// model's complete list, and deriving it from a filtered one would address these rows
    /// differently from the rest of the app.
    fn of(tab: &Tab) -> Self {
        let mut verbs = Self {
            per_profile: Vec::new(),
            about: Vec::new(),
            create: Vec::new(),
        };
        for action in section_actions(tab) {
            match action.id {
                TrayAction::SetActiveProfile { .. }
                | TrayAction::SetProfileVisibility { .. }
                | TrayAction::DeleteProfile { .. }
                | TrayAction::RepairProfileBody { .. } => verbs.per_profile.push(action),
                TrayAction::CreateProfile => verbs.create.push(action),
                _ => verbs.about.push(action),
            }
        }
        verbs
    }

    /// The verbs that act on `profile`, found by the index in each action's payload.
    fn for_profile(&self, profile: &ProfileRow) -> Vec<Action<TrayAction>> {
        self.per_profile
            .iter()
            .filter(|action| acts_on(action.id) == Some(profile.ix.0))
            .cloned()
            .collect()
    }
}

/// Which profile an action acts on, or `None` when it acts on none.
fn acts_on(action: TrayAction) -> Option<u32> {
    match action {
        TrayAction::SetActiveProfile { ix }
        | TrayAction::SetProfileVisibility { ix, .. }
        | TrayAction::DeleteProfile { ix }
        | TrayAction::RepairProfileBody { ix } => Some(ix),
        _ => None,
    }
}

/// Every profile verb this card DRAWS for `facts`, so the Account pane's completeness sweep can sum
/// it in without rebuilding the sort.
///
/// It follows [`list`]'s own rule: the per-profile verbs reach the screen only for profiles that are
/// on a READ list, because a control acting on a profile nobody has confirmed exists is exactly what
/// the three-state reading is for. The explainer is drawn in every state.
#[cfg(test)]
pub(crate) fn drawn_actions(tab: &Tab, facts: &PaneFacts) -> Vec<TrayAction> {
    let verbs = ProfileVerbs::of(tab);
    facts
        .profiles
        .rows()
        .unwrap_or_default()
        .iter()
        .flat_map(|profile| verbs.for_profile(profile))
        .chain(verbs.about.iter().cloned())
        .map(|action| action.id)
        .collect()
}

/// The rows of the model's profile section, weighted through the ONE shared derivation.
fn section_actions(tab: &Tab) -> Vec<Action<TrayAction>> {
    let mut seen = std::collections::HashMap::new();
    tab.sections
        .iter()
        .flat_map(|section| {
            let drawn = super::actions_in(section.rows.iter().cloned(), &mut seen);
            match section.heading.as_deref() == Some(crate::window_model::PROFILES_HEADING) {
                true => drawn,
                false => Vec::new(),
            }
        })
        .collect()
}

/// What a profile is, and why one cannot be created here.
///
/// A recessed panel INSIDE the card rather than a card of its own: it is about the same subject the
/// list is, and a person reading an empty list needs the explanation without changing where they are
/// looking.
/// The panel says one of two things, and never both:
///
/// * a state that WITHHOLDS the offer explains itself — what is still being checked, or which
///   measured fact is in the way and what to do about it;
/// * a state that can honour it draws the CONTROL, under the sentence saying what a profile is.
///
/// The panel used to draw nothing at all for a capable node, which was right while there was no
/// control: announcing a capability with nothing to press is the dead end `professional-ui` forbids
/// outright. The control exists now, so silence would be the opposite defect — a card that can offer
/// something and does not say so.
///
/// Note what carries the safety. It is NOT this match: the offer is withheld by the MODEL, which
/// builds no `CreateProfile` row unless `ProfileCreation::is_possible()`. So a mistake here draws an
/// empty panel, never a live control on a node that cannot honour it.
fn create_panel(
    flow: &mut Flow,
    t: &Tokens,
    creation: ProfileCreation,
    reading: &ProfilesReading,
    verbs: &ProfileVerbs,
) -> Option<TrayAction> {
    let sentence = match creation {
        // Nobody has asked the node yet, so the panel names the READ rather than an outcome. Drawing
        // a blocked cause here would tell a person with a stopped node that nothing is missing from
        // their setup (dig_ecosystem#2690).
        ProfileCreation::Unknown => copy::profiles::CHECKING_CREATION.to_string(),
        // Named from the SAME reading the rows above were drawn from, so the sentence and the
        // list cannot call one profile two things (dig_ecosystem#2981).
        ProfileCreation::Blocked(blocked) => {
            copy::profiles::cannot_create(blocked, crate::profiles::ProfileNames::of(reading))
        }
        // What a profile IS, reused rather than rewritten: the control's own label says what
        // pressing it does, and the funding window it opens states the cost. A second sentence here
        // promising that creation COMPLETES would be false — nothing in this build runs the ceremony
        // yet (dig_ecosystem#2952).
        ProfileCreation::Possible => crate::profiles::copy::WHAT_A_PROFILE_IS.to_string(),
    };
    let mut pressed = None;
    flow.place(|ui, at| {
        (
            card::panel(ui, at, t, Some(copy::profiles::CREATE_PANEL), |inner| {
                inner.place(|ui, at| (text::body(ui, at, t, &sentence), ()));
                if !verbs.create.is_empty() {
                    pressed = wizard(inner, t, &verbs.create);
                }
            }),
            (),
        )
    });
    pressed
}

/// The creation wizard: what the new profile will HOLD, collected before anything is spent.
///
/// # Why the form is here rather than after the mint
///
/// The store singleton is launched at the seed's root, so whatever this collects is committed by
/// the store's very first generation (dig_ecosystem#3038). Filling the same boxes in after the mint
/// confirms is a second chain write for the same result, which the person pays for.
///
/// Drawn only when the model built a create row, so the form never appears on a machine that could
/// not honour it — the offer is withheld by the MODEL, exactly as the control is.
fn wizard(flow: &mut Flow, t: &Tokens, create: &[Action<TrayAction>]) -> Option<TrayAction> {
    let live = flow.live();
    let mut form = flow.place(|ui, _| (0.0, load_wizard(ui)));
    form.collect_a_finished_choice();

    flow.gap(space::S3);
    flow.place(|ui, at| (text::body(ui, at, t, copy::profiles::SEED_INVITATION), ()));
    flow.gap(space::S3);
    profile_form::draw_fields(flow, t, &mut form, WIZARD_SCOPE);
    flow.gap(space::S3);
    flow.place(|ui, at| {
        (
            text::caption(ui, at, t, copy::profiles::SEED_SAVES_A_WRITE),
            (),
        )
    });

    // An empty form is allowed to mint; a form with something WRONG in it is not, because at mint
    // time a refused value is money already committed.
    let ready = seed::is_mintable(&form.draft);
    if !ready {
        flow.gap(space::S2);
        flow.place(|ui, at| {
            (
                text::caption(ui, at, t, copy::profiles::SEED_HAS_A_PROBLEM),
                (),
            )
        });
    }

    flow.gap(space::S3);
    let offered: Vec<Action<TrayAction>> = create
        .iter()
        .map(|verb| Action {
            // The label is the model's, verbatim. What this panel decides is only whether the
            // control is pressable right now.
            enabled: verb.enabled && ready,
            ..verb.clone()
        })
        .collect();
    let pressed = flow.place(|ui, at| action::buttons(ui, at, t, live, &offered));

    // Handed over BEFORE the verb is reported, because reporting it is what starts the ceremony:
    // a mint that read the holder first would seed the store from the previous form.
    if pressed.is_some() {
        if let Some(request) = ProfileSeedRequest::of_draft(&form.draft) {
            request.collect();
        }
    }
    flow.place(|ui, _| (0.0, store_wizard(&form, ui)));
    pressed
}

/// The element-id namespace the wizard's inputs live in — distinct from the editor's, which may be
/// drawn on the same tab.
const WIZARD_SCOPE: Scope = Scope("dig-window-profile-create");

/// The id the wizard's form is kept under, for the life of the window.
fn wizard_id() -> egui::Id {
    egui::Id::new("dig-profile-create-session")
}

/// The wizard's form as it stands, or an empty one the first time it is drawn.
///
/// Unlike the editor's, this form is never rebuilt from underneath: there is no profile to re-read,
/// so anything typed is the only copy of it and dropping it would lose a person's work mid-form.
fn load_wizard(ui: &egui::Ui) -> Form {
    ui.data(|d| d.get_temp::<Form>(wizard_id()))
        .unwrap_or_else(|| Form::over(ProfileDraft::empty()))
}

/// Keep the wizard's form for the next frame.
fn store_wizard(form: &Form, ui: &egui::Ui) {
    ui.data_mut(|d| d.insert_temp(wizard_id(), form.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::profile_session::test_support::{
        expected_did, expected_store_id, session_with,
    };
    use crate::profiles::{CreationBlocked, ProfileNames, ProfilesUnknown};

    /// The naming these assertions compare against: no list, so every profile is its ordinal.
    ///
    /// The card under test is fed an EMPTY reading in these fixtures, which names nothing either —
    /// so the two agree by construction. The label-derived naming has its own test, where a
    /// labelled row is the whole point (`the_card_names_a_profile_the_way_its_row_does`).
    const NAMES: ProfileNames<'static> = ProfileNames::NONE;
    use crate::tray_menu::{AccountState, TrayView};
    use crate::window_model::TabId;
    use dig_account::registry::ProfileVisibility;
    use dig_account::ProfileIx;

    /// A view holding `profiles`, on an otherwise working machine with an open account.
    fn view_with(profiles: ProfilesReading) -> TrayView {
        TrayView {
            running: true,
            node_connected: true,
            account: Some(AccountState::Unlocked { recoverable: true }),
            profile_id: Some("a".repeat(64)),
            profiles,
            ..TrayView::default()
        }
    }

    /// The registry a fixture with `profiles` reads as, hiding whichever indices `hidden` names.
    fn reading_of(profiles: &[(ProfileIx, Option<&str>)], hidden: &[ProfileIx]) -> ProfilesReading {
        let mut registry = session_with(profiles).with_registry(Clone::clone);
        for ix in hidden {
            registry
                .set_visibility(*ix, ProfileVisibility::HiddenFromLists)
                .expect("a non-active profile can be hidden");
        }
        ProfilesReading::of_registry(&registry)
    }

    /// Every string the card painted at `width` for `view`.
    ///
    /// Drawn through the REAL model and the REAL card, because the property under test is what a
    /// person SEES: a helper returning the right sentence proves nothing about a card that draws an
    /// empty list beside it.
    fn card_says(view: &TrayView, width: f32) -> String {
        card_says_on(view, width, None)
    }

    /// The same, with the browser opened on the profile at `showing`.
    ///
    /// The pager remembers a `ProfileIx`, so a test names the profile it wants to look at rather
    /// than a page number — which is the same property production relies on, exercised the same
    /// way. Without this a test could only ever read the first page.
    fn card_says_on(view: &TrayView, width: f32, showing: Option<ProfileIx>) -> String {
        let tab = crate::window_model::build(view)
            .tab(TabId::Account)
            .cloned()
            .expect("the Account tab is emitted in every account state");
        let facts = PaneFacts::of_tray(view);

        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let t = crate::confirm::gui::theme::Theme::Light.tokens();
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::Vec2::new(width, 8_000.0));
        if let Some(ix) = showing {
            ctx.data_mut(|d| d.insert_temp(super::pager_id(), ix.0));
        }

        let mut output = egui::FullOutput::default();
        // Two frames: the first builds the font atlas, the second lays out against it.
        for _ in 0..2 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("profiles-card-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            let column = egui::Rect::from_min_size(
                                screen.left_top(),
                                egui::Vec2::new(width - space::S5 * 2.0, f32::INFINITY),
                            );
                            let mut flow = Flow::new(ui, column, true);
                            super::card(&mut flow, &t, &tab, &facts);
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

    /// **A profile list still being read is never drawn as an account with no profiles.**
    ///
    /// The headline honesty property. Every real user reads `Known(vec![])`, so an implementation
    /// that treated "no rows" as the empty state — the obvious `Option<&[_]>` reduction — is right
    /// about the common case and wrong about the moment the window opens, which is the moment a
    /// person actually looks.
    ///
    /// Three actors, because the three states must reach the screen as three different sentences.
    #[test]
    fn a_list_still_being_read_is_not_drawn_as_an_account_with_no_profiles() {
        let pending = card_says(&view_with(ProfilesReading::Pending), 960.0);
        assert!(
            pending.contains(copy::profiles::PENDING),
            "a read in flight did not say so: {pending}"
        );
        assert!(
            !pending.contains(copy::profiles::EMPTY),
            "a read that has not answered was drawn as an account holding no profiles: {pending}"
        );

        // The control: the registry ANSWERED with nothing, which is a different claim.
        let answered = card_says(&view_with(ProfilesReading::Known(Vec::new())), 960.0);
        assert!(
            answered.contains(copy::profiles::EMPTY),
            "an account that really has no profiles was not told so: {answered}"
        );
        assert!(
            !answered.contains(copy::profiles::PENDING),
            "an answered read was drawn as one still going: {answered}"
        );

        // And the third: the registry could not be read at all, which claims nothing about how many
        // profiles the person has.
        let why = "the stored profile registry is unusable: trailing comma";
        let broken = card_says(
            &view_with(ProfilesReading::Unknown(ProfilesUnknown::Unreadable(
                why.to_owned(),
            ))),
            960.0,
        );
        assert!(
            broken.contains(why),
            "the loader's own words never reached the screen, so a hand-edited file and a \
             permissions fault read identically: {broken}"
        );
        for claim in [copy::profiles::EMPTY, copy::profiles::PENDING] {
            assert!(
                !broken.contains(claim),
                "an unreadable registry was drawn as an empty or still-loading list, which tells \
                 somebody who may hold several profiles that they hold none: {broken}"
            );
        }
    }

    /// **The empty state explains, rather than reading as an error or as a load that never
    /// finishes.**
    ///
    /// The state EVERY real user is in, so the assertion is on what the sentence has to do: say what
    /// a profile is, say the account works without one, and account for the missing create button.
    /// The wallet half is what stops an empty profile list implying the wallet is unusable, on a tab
    /// inches from a real fundable address.
    #[test]
    fn the_empty_state_explains_what_a_profile_is_and_that_the_account_still_works() {
        let said = copy::profiles::EMPTY.to_lowercase();
        for expected in ["profile is", "publish", "funds", "reads"] {
            assert!(
                said.contains(expected),
                "the empty state never mentions “{expected}”, so a person reads an empty list with \
                 nothing to make of it: {said}"
            );
        }
        for alarm in ["error", "failed", "could not"] {
            assert!(
                !said.contains(alarm),
                "the ordinary state of every account is worded as a fault: {said}"
            );
        }
    }

    /// **Every profile is reachable, ONE page at a time, each with its own ids and badges**
    /// (dig_ecosystem#3069, criterion 1).
    ///
    /// This replaces `every_profile_reaches_the_card_with_its_own_did_and_badges`, which asserted
    /// all three profiles were on screen together — true of the stacked list and false by design of
    /// the pager. The property it protected survives and is what is checked here: no profile
    /// becomes unreachable, and each still carries its own DID, its own store and its own badges.
    ///
    /// # Why the fixture hides the MIDDLE profile
    ///
    /// A card that dropped hidden rows loses exactly one, and one that badged every row identically
    /// disagrees at two of the three. A fixture hiding all or none could tell neither apart.
    ///
    /// # Why the OTHER profiles are required ABSENT
    ///
    /// That is the pager working. Without this leg, the shipped stacked list passes every positive
    /// assertion here — it draws all three ids on every page — so nothing would distinguish a
    /// browser from the layout it replaces.
    #[test]
    fn every_profile_is_reachable_one_page_at_a_time_with_its_own_ids_and_badges() {
        let listed = [ProfileIx::ROOT, ProfileIx(1), ProfileIx(2)];
        let reading = reading_of(
            &[
                (ProfileIx::ROOT, Some("home")),
                (ProfileIx(1), Some("work")),
                (ProfileIx(2), None),
            ],
            &[ProfileIx(1)],
        );

        // Asserted at BOTH widths the window spans, because the badge row and the copy control both
        // reflow at the narrow one.
        for width in [960.0_f32, 480.0] {
            for (page, ix) in listed.into_iter().enumerate() {
                let said = card_says_on(&view_with(reading.clone()), width, Some(ix));

                assert!(
                    said.contains(&expected_did(ix)),
                    "at {width} px profile {ix} cannot be browsed to: {said}"
                );
                // In FULL, at every width. A 66-character store id beside a 60-odd-character DID is
                // exactly the pair that overflows the narrow card, and a truncation introduced to
                // relieve that would hide characters the reader has no other way to reach.
                assert!(
                    said.contains(&expected_store_id(ix)),
                    "at {width} px profile {ix}'s store id never reached the card in full, so the \
                     half of the profile that holds its content is unnameable: {said}"
                );
                assert!(
                    said.contains(&format!("Profile {} of 3", page + 1)),
                    "at {width} px the browser does not say where in the list this is: {said}"
                );

                // And nobody else's ids are on this page.
                for other in listed.into_iter().filter(|other| *other != ix) {
                    assert!(
                        !said.contains(&expected_did(other)),
                        "at {width} px profile {other} is drawn on profile {ix}'s page, so the \
                         browser is showing the whole stacked list: {said}"
                    );
                }
            }

            // The badges belong to the profile whose page they are on, and to no other.
            let active_page =
                card_says_on(&view_with(reading.clone()), width, Some(ProfileIx::ROOT));
            assert!(
                active_page.contains(copy::profiles::ACTIVE_BADGE),
                "at {width} px nothing says the profile in use is in use: {active_page}"
            );
            assert!(
                !active_page.contains(copy::profiles::HIDDEN_BADGE),
                "at {width} px the profile in use is badged as hidden: {active_page}"
            );

            let hidden_page = card_says_on(&view_with(reading.clone()), width, Some(ProfileIx(1)));
            assert!(
                hidden_page.contains(copy::profiles::HIDDEN_BADGE),
                "at {width} px a hidden profile is shown without saying it is hidden, so the \
                 control beside it reads as hiding something already visible: {hidden_page}"
            );
            assert!(
                !hidden_page.contains(copy::profiles::ACTIVE_BADGE),
                "at {width} px a profile that is not in use is badged as in use: {hidden_page}"
            );
            assert!(
                hidden_page.contains("\u{201c}work\u{201d}"),
                "at {width} px a profile's own name did not reach its page: {hidden_page}"
            );
        }
    }

    /// **A page is remembered by the profile's INDEX, so a delete cannot silently swap who is on
    /// screen** (the pager hazard).
    ///
    /// The fixture is the exact failure: three profiles, the browser on the SECOND, and then that
    /// second profile is gone. An ordinal-keyed pager stays on page 2 and now shows a different
    /// person's identity — with a Delete control on it — having changed nothing visible.
    ///
    /// The control leg is the same list with the profile still present, which must resolve to its
    /// own page rather than to the fallback.
    #[test]
    fn a_deleted_profile_does_not_leave_the_browser_pointing_at_its_neighbour() {
        let full = reading_of(
            &[
                (ProfileIx::ROOT, Some("home")),
                (ProfileIx(1), Some("work")),
                (ProfileIx(2), Some("spare")),
            ],
            &[],
        );
        let after_delete = reading_of(
            &[
                (ProfileIx::ROOT, Some("home")),
                (ProfileIx(2), Some("spare")),
            ],
            &[],
        );

        let still_there = card_says_on(&view_with(full), 960.0, Some(ProfileIx(1)));
        assert!(
            still_there.contains(&expected_did(ProfileIx(1))),
            "the browser did not open on the profile it was remembering: {still_there}"
        );

        let gone = card_says_on(&view_with(after_delete), 960.0, Some(ProfileIx(1)));
        assert!(
            gone.contains(&expected_did(ProfileIx::ROOT)),
            "a browser remembering a deleted profile did not fall back to the first page: {gone}"
        );
        assert!(
            !gone.contains(&expected_did(ProfileIx(2))),
            "the browser landed on the profile that inherited the deleted one's POSITION, which is \
             a different identity under the same page number, with a Delete control on it: {gone}"
        );
    }

    /// **Every profile has an Edit control, not only the one in use** (dig_ecosystem#3069,
    /// criterion 4).
    ///
    /// The control is drawn for the active profile AND for one that is not, because the reduction
    /// this rejects — offering Edit only where the app can currently save — would leave a person
    /// making a chain-visible state change to fix a typo somewhere else.
    #[test]
    fn every_profile_is_offered_a_way_to_edit_it() {
        let reading = reading_of(
            &[
                (ProfileIx::ROOT, Some("home")),
                (ProfileIx(1), Some("work")),
            ],
            &[],
        );

        for (ix, name) in [
            (ProfileIx::ROOT, "\u{201c}home\u{201d}"),
            (ProfileIx(1), "\u{201c}work\u{201d}"),
        ] {
            let said = card_says_on(&view_with(reading.clone()), 960.0, Some(ix));
            assert!(
                said.contains(&copy::profiles::edit(name)),
                "profile {ix} is offered no way to change what it says: {said}"
            );
        }
    }

    /// **The card says what a switch changes BEFORE anything is pressed** — and says nothing about
    /// it when no switch is on offer.
    ///
    /// Both sides. The caution is the ticket's "say so before it happens", and a card that printed
    /// it unconditionally would warn a single-profile account about an act it cannot perform — which
    /// is how people learn to skip the paragraph that matters.
    #[test]
    fn the_switch_caution_is_drawn_where_a_switch_is_possible_and_nowhere_else() {
        let two = reading_of(
            &[
                (ProfileIx::ROOT, Some("home")),
                (ProfileIx(1), Some("work")),
            ],
            &[],
        );
        let said = card_says(&view_with(two), 960.0);
        assert!(
            said.contains(copy::profiles::SWITCH_CAUTION),
            "a card offering a switch never says what one changes: {said}"
        );

        let alone = reading_of(&[(ProfileIx::ROOT, Some("home"))], &[]);
        let lonely = card_says(&view_with(alone), 960.0);
        assert!(
            !lonely.contains(copy::profiles::SWITCH_CAUTION),
            "an account with one profile is warned about switching, which it cannot do: {lonely}"
        );
        // The control: the lone profile IS drawn, so the assertion above is about the caution rather
        // than about a card that painted nothing.
        assert!(
            lonely.contains(&expected_did(ProfileIx::ROOT)),
            "the single-profile card drew no profile at all: {lonely}"
        );
    }

    /// **Each profile's verbs are matched to it by index, never by position.**
    ///
    /// The fixture's indices are deliberately NOT `0,1,2`: a gap between them means a card that
    /// zipped the model's rows against the list in order agrees with this one only while the two
    /// happen to line up. With `ROOT, 2, 5` the wrong implementation hands profile 2 the verbs built
    /// for profile 5.
    #[test]
    fn a_profiles_verbs_are_found_by_its_index_and_not_by_its_place_in_the_list() {
        let reading = reading_of(
            &[
                (ProfileIx::ROOT, Some("home")),
                (ProfileIx(2), Some("work")),
                (ProfileIx(5), Some("play")),
            ],
            &[],
        );
        let view = view_with(reading.clone());
        let tab = crate::window_model::build(&view)
            .tab(TabId::Account)
            .cloned()
            .expect("Account");
        let verbs = ProfileVerbs::of(&tab);

        for profile in reading.rows().expect("a read list") {
            for action in verbs.for_profile(profile) {
                assert_eq!(
                    acts_on(action.id),
                    Some(profile.ix.0),
                    "“{}” was drawn on profile {}'s row and acts on another",
                    action.label,
                    profile.ix
                );
            }
        }

        // The active profile gets no verbs at all: nothing to switch to, and dig-account refuses to
        // hide it. Its absence is explained by `ACTIVE_CANNOT_HIDE`, drawn under the list.
        let active = reading
            .rows()
            .expect("a read list")
            .iter()
            .find(|row| row.active)
            .expect("one profile is active");
        assert!(
            verbs.for_profile(active).is_empty(),
            "the profile in use was offered a control that would refuse"
        );
        assert!(
            !verbs.for_profile(&reading.rows().unwrap()[1]).is_empty(),
            "no profile got any verb, so the assertion above proves nothing"
        );
    }

    /// **Every verb the model put in the profile section is drawn, exactly once.**
    ///
    /// The rule the whole pane system rests on: a pane renders the model's decisions and adds none.
    /// A verb in NEITHER group is a control the app claims to offer and does not; one in BOTH is two
    /// controls a person has to tell apart before pressing either.
    #[test]
    fn the_card_draws_every_profile_verb_the_model_offers_and_no_others() {
        let reading = reading_of(
            &[(ProfileIx::ROOT, Some("home")), (ProfileIx(1), None)],
            &[ProfileIx(1)],
        );
        let view = view_with(reading.clone());
        let tab = crate::window_model::build(&view)
            .tab(TabId::Account)
            .cloned()
            .expect("Account");
        let verbs = ProfileVerbs::of(&tab);

        let mut drawn: Vec<TrayAction> = reading
            .rows()
            .expect("a read list")
            .iter()
            .flat_map(|profile| verbs.for_profile(profile))
            .map(|action| action.id)
            .chain(verbs.about.iter().map(|action| action.id))
            .collect();
        let mut offered: Vec<TrayAction> = section_actions(&tab)
            .into_iter()
            .map(|action| action.id)
            .collect();

        assert!(
            offered.len() > 2,
            "the fixture offers too few verbs to tell a filter from an empty section: {offered:?}"
        );
        drawn.sort_by_key(|a| format!("{a:?}"));
        offered.sort_by_key(|a| format!("{a:?}"));
        assert_eq!(
            drawn, offered,
            "the profiles card's buttons are not the model's profile rows"
        );
    }

    /// **While nobody has measured the node, the card says it is checking — not that the build cannot
    /// reach the chain** (dig_ecosystem#2690).
    ///
    /// Makes impossible: the sentence *"nothing is missing from your setup and there is nothing for
    /// you to do"* shown to a person whose node is simply stopped. That is the one blocked sentence
    /// that also tells them to stop looking, so rendering it for an unmeasured node costs them the
    /// only action that would help.
    ///
    /// # Why the fixture needs the two negative legs
    ///
    /// A test that only asserted the checking sentence appears would pass on a card that drew BOTH —
    /// the honest one and a definite cause beside it — which is the same lie with extra words. So each
    /// blocked sentence is required ABSENT, and the control leg requires the same card to still draw a
    /// blocked sentence when a reading really was taken, so "draws nothing ever" cannot pass either.
    #[test]
    fn an_unmeasured_node_is_drawn_as_checking_and_not_as_an_unreachable_chain() {
        let checking = TrayView {
            profile_creation: ProfileCreation::Unknown,
            ..view_with(ProfilesReading::Known(Vec::new()))
        };
        let painted = card_says(&checking, 960.0);

        assert!(
            painted.contains(copy::profiles::CHECKING_CREATION),
            "an unmeasured node drew no honest waiting state: {painted}"
        );
        for blocked in CreationBlocked::EVERY {
            assert!(
                !painted.contains(&copy::profiles::cannot_create(blocked, NAMES)),
                "{blocked:?} was stated as a cause on a node nobody had measured: {painted}"
            );
        }

        // Control: a reading that WAS taken still explains itself, so this cannot be satisfied by a
        // card that has stopped drawing the panel at all.
        let measured = TrayView {
            profile_creation: ProfileCreation::Blocked(CreationBlocked::NoChainTransport),
            ..view_with(ProfilesReading::Known(Vec::new()))
        };
        let measured_says = card_says(&measured, 960.0);
        assert!(
            measured_says.contains(&copy::profiles::cannot_create(
                CreationBlocked::NoChainTransport,
                NAMES
            )),
            "a measured blocker stopped being explained: {measured_says}"
        );
        assert!(
            !measured_says.contains(copy::profiles::CHECKING_CREATION),
            "a measured blocker was ALSO drawn as still being checked, which is two answers to one \
             question: {measured_says}"
        );
    }

    /// **A node that CAN honour the offer DRAWS the control** (dig_ecosystem#2939, #2946).
    ///
    /// This replaces `a_capable_node_draws_no_offer_it_cannot_yet_honour`, which was correct while
    /// the card had no control to draw and is wrong by design now that it has one. Its negative
    /// legs are kept — no blocked sentence and no still-checking sentence for a node that already
    /// answered — and the POSITIVE leg is new, which is the half dig_ecosystem#2946 was filed
    /// about: a test asserting only absences passes just as happily on a pane that painted
    /// NOTHING AT ALL, and painting nothing is what a regression here actually produces.
    ///
    /// Proved load-bearing by stubbing the panel's render to draw nothing and watching this fail;
    /// the old test stayed green through the same mutation.
    #[test]
    fn a_capable_node_draws_the_control_it_can_honour() {
        let view = TrayView {
            profile_creation: ProfileCreation::Possible,
            ..view_with(ProfilesReading::Known(Vec::new()))
        };
        let painted = card_says(&view, 960.0);

        assert!(
            painted.contains(crate::tray_menu::CREATE_PROFILE_LABEL),
            "a node that can honour creation drew no way to reach it: {painted}"
        );
        assert!(
            painted.contains(copy::profiles::CREATE_PANEL),
            "the control was drawn outside the panel that explains what it is for: {painted}"
        );
        assert!(
            !painted.contains(copy::profiles::CHECKING_CREATION),
            "a node that already answered is drawn as still being checked: {painted}"
        );
        for blocked in CreationBlocked::EVERY {
            assert!(
                !painted.contains(&copy::profiles::cannot_create(blocked, NAMES)),
                "a node that CAN mint is told {blocked:?} is missing: {painted}"
            );
        }
    }

    /// **The wizard collects the new profile's content, and only where a mint could honour it.**
    ///
    /// The point of the form is that the store singleton launches at the seed's root, so anything
    /// collected here is committed by the store's first generation instead of costing a second
    /// chain write. A form drawn on a node that cannot mint would invite somebody to type a
    /// biography into a machine that has nowhere to put it, so the withheld arm is the control —
    /// without it, an unconditional form passes this test.
    #[test]
    fn the_wizard_collects_the_profiles_content_where_a_mint_is_possible_and_nowhere_else() {
        let capable = TrayView {
            profile_creation: ProfileCreation::Possible,
            ..view_with(ProfilesReading::Known(Vec::new()))
        };
        let painted = card_says(&capable, 960.0);

        // The Basic set is on screen; the Enhanced set is one press away, named and summarised so
        // nobody has to guess what is inside it (dig_ecosystem#3069, criterion 8). Both halves are
        // asserted, because "collects everything" and "opens with three boxes" are the two claims
        // this form has to hold at once.
        use crate::profile_edit::{FieldGroup, ProfileField};
        for field in ProfileField::of_group(FieldGroup::Basic) {
            assert!(
                painted.contains(field.label()),
                "the wizard's opening form collects nothing for {field:?}: {painted}"
            );
        }
        for group in FieldGroup::ALL {
            assert!(
                painted.contains(group.title()) && painted.contains(group.summary()),
                "{group:?} is neither drawn nor named, so whatever it holds is unreachable: \
                 {painted}"
            );
        }
        // And the fold is REAL: the collapsed set's fields are genuinely not on screen. Without
        // this leg, a form that drew all eight boxes under two headings would pass everything
        // above while being exactly the intimidating form the redesign removes.
        //
        // Read from each field's HELP sentence rather than from its LABEL, because the Enhanced
        // fieldset's summary names the fields it contains — that is its whole job — so a label
        // sweep matches the summary and reports a fold that works as broken. (It did.)
        for field in ProfileField::of_group(FieldGroup::Enhanced) {
            assert!(
                !painted.contains(field.help()),
                "{field:?} is drawn although its fieldset is collapsed: {painted}"
            );
        }
        // The control: the SAME reading, over a Basic field, must find its help — so the sweep
        // above is about the fold and not about a sentence the form never paints anywhere.
        assert!(
            painted.contains(ProfileField::DisplayName.help()),
            "no field's help reaches the screen, so the absences above prove nothing: {painted}"
        );
        assert!(
            painted.contains(copy::profiles::SEED_INVITATION),
            "the form never says every box is optional, so it reads as a set of requirements:              {painted}"
        );
        assert!(
            painted.contains(copy::profiles::SEED_SAVES_A_WRITE),
            "nothing says why filling this in now is worth doing: {painted}"
        );

        // The control: a node nobody has spoken to. It answers `blocked() == None` exactly as
        // `Possible` does, so a form gated on anything but the ARM is drawn here too.
        let unmeasured = TrayView {
            profile_creation: ProfileCreation::Unknown,
            ..view_with(ProfilesReading::Known(Vec::new()))
        };
        let quiet = card_says(&unmeasured, 960.0);
        assert!(
            !quiet.contains(copy::profiles::SEED_INVITATION),
            "a node nobody has measured invited somebody to fill in a profile it may not be able              to mint: {quiet}"
        );
    }

    /// **A value that could not be published stops the creation before the money moves.**
    ///
    /// At mint time a refused value is money already committed and a profile born holding a
    /// filename, so the gate is the wizard's, not the ceremony's. Pinned from both sides against
    /// the same field: an empty form -- the person who wants only a DID -- must remain mintable,
    /// which is the half a `is_committable`-style gate silently breaks.
    #[test]
    fn a_wrong_value_blocks_the_creation_while_an_empty_form_does_not() {
        use crate::profile_edit::{seed, ProfileDraft, ProfileField};

        let empty = ProfileDraft::empty();
        assert!(
            seed::is_mintable(&empty),
            "a person who wants only a DID cannot create one"
        );

        let mut mistyped = ProfileDraft::empty();
        mistyped.set(ProfileField::XchAddress, "xch1notarealaddress");
        assert!(
            !seed::is_mintable(&mistyped),
            "a mistyped payment address would have been minted into the profile"
        );

        let mut pictured = ProfileDraft::empty();
        pictured.set(ProfileField::Avatar, "me.png");
        assert!(
            !seed::is_mintable(&pictured),
            "a filename would have been published where every client looks for a picture"
        );
    }

    /// **A card that cannot honour the offer draws no control — for a MEASURED blocker and for an
    /// unmeasured node alike** (dig_ecosystem#2939, #2690).
    ///
    /// The other direction of the test above, and the one that matters for money: the control leads
    /// to a funding window, so drawing it where the ceremony would refuse walks somebody toward a
    /// spend that cannot proceed.
    ///
    /// `Unknown` is the leg that would be missed. It answers `blocked() == None` exactly as
    /// `Possible` does, so any gate written against `blocked()` rather than against the ARM draws
    /// the control for a node nobody has spoken to.
    #[test]
    fn a_card_that_cannot_honour_creation_draws_no_control() {
        let mut withheld = vec![ProfileCreation::Unknown];
        withheld.extend(CreationBlocked::EVERY.map(ProfileCreation::Blocked));

        for creation in withheld {
            let view = TrayView {
                profile_creation: creation,
                ..view_with(ProfilesReading::Known(Vec::new()))
            };
            let painted = card_says(&view, 960.0);
            assert!(
                !painted.contains(crate::tray_menu::CREATE_PROFILE_LABEL),
                "{creation:?} drew a control leading to a funding window it cannot honour: {painted}"
            );
        }

        // Control: the SAME card, the one arm that CAN honour it, so "never draws a control"
        // cannot pass this.
        let capable = TrayView {
            profile_creation: ProfileCreation::Possible,
            ..view_with(ProfilesReading::Known(Vec::new()))
        };
        assert!(
            card_says(&capable, 960.0).contains(crate::tray_menu::CREATE_PROFILE_LABEL),
            "no state draws the control, so the withholding above proves nothing"
        );
    }

    /// **Where the card offers no way to create a profile, it says WHY — one cause, one sentence,
    /// one remedy.**
    ///
    /// The structural half is held by `a_card_that_cannot_honour_creation_draws_no_control`: the
    /// model builds no `CreateProfile` row for these arms, so the absence cannot be flipped on by a
    /// mistaken `enabled: true`. What is asserted here is the half a person reads — that the
    /// absence is explained rather than left as a missing button.
    ///
    /// Every blocked arm is drawn, because the missing pieces need different sentences and a card
    /// that showed one of them for all would send most of its readers after the wrong fault.
    #[test]
    fn the_card_explains_why_it_offers_no_way_to_create_a_profile() {
        let mut said = Vec::new();
        for blocked in CreationBlocked::EVERY {
            let creation = ProfileCreation::Blocked(blocked);
            assert!(
                !creation.is_possible(),
                "no build shipped so far can create a profile, so a fixture that says otherwise                  is not a state this card can be in"
            );
            let view = TrayView {
                profile_creation: creation,
                ..view_with(ProfilesReading::Known(Vec::new()))
            };
            let painted = card_says(&view, 960.0);
            assert!(
                painted.contains(&copy::profiles::cannot_create(blocked, NAMES)),
                "{blocked:?} did not reach the card as its own sentence: {painted}"
            );
            said.push(copy::profiles::cannot_create(blocked, NAMES));
        }
        assert_ne!(
            said[0], said[1],
            "both missing pieces are explained in the same words, so one reader is sent after a \
             fault they do not have"
        );

        // Each blocker names the remedy for ITS OWN cause. Asserted per-arm rather than as "some
        // remedy word appears somewhere", because the two causes have OPPOSITE remedies — a stopped
        // node is started, an old one is updated — and a card that offered the wrong one sends a
        // person to reinstall software that is working, or to restart a node that is already
        // running. A single sentence carrying both words would satisfy a looser check.
        let remedies = [
            (CreationBlocked::NoChainTransport, "start", "update"),
            (CreationBlocked::NoLineageWalk, "update", "start"),
        ];
        for (blocked, remedy, other) in remedies {
            let lowered = copy::profiles::cannot_create(blocked, NAMES).to_lowercase();
            assert!(
                lowered.contains(remedy),
                "{blocked:?} does not tell the person to {remedy} anything, so a measured cause \
                 reads as an absence they can do nothing about: {lowered}"
            );
            assert!(
                !lowered.contains(other),
                "{blocked:?} sends the reader after the OTHER cause's remedy: {lowered}"
            );
        }

        for sentence in &said {
            let lowered = sentence.to_lowercase();
            // The claim was true only while creation came from a hardcoded seam. It is now read off
            // the node, so both arms describe THIS MACHINE — and telling somebody whose node is
            // merely stopped that the capability is missing from DIG withholds the one action that
            // would fix it (dig_ecosystem#2398).
            assert!(
                !lowered.contains("not available in this version"),
                "a MEASURED blocker is reported as a missing DIG capability: {lowered}"
            );
            assert!(
                !lowered.contains("nothing for you to do"),
                "a person with a fixable node is told there is nothing they can do: {lowered}"
            );
            assert!(
                !lowered.contains("optional"),
                "the word #1820 settled against is back: {lowered}"
            );
        }
    }

    /// **The way to put a profile in use is on the card — and a lone-profile account is told what
    /// would produce one** (dig_ecosystem#3057).
    ///
    /// A user reported seeing no *set active* and no *add new* control. Both exist, and the fixture
    /// here is what makes that checkable rather than asserted: two profiles produce a real switch
    /// control naming the one NOT in use, and a capable node produces the create control.
    ///
    /// # Why the one-profile leg is the load-bearing half
    ///
    /// With a single profile the card draws no per-profile control at all — correctly, since there
    /// is nothing to switch to and the profile in use cannot be hidden — so it said nothing about
    /// multiplicity to exactly the person who would conclude it is unsupported. The control is the
    /// two-profile capture, which must NOT carry that sentence: an implementation that printed it
    /// unconditionally would be telling somebody with a switch in front of them that they have
    /// nothing to switch between.
    #[test]
    fn the_switch_control_appears_with_a_second_profile_and_is_explained_without_one() {
        let two = reading_of(
            &[
                (ProfileIx::ROOT, Some("home")),
                (ProfileIx(1), Some("work")),
            ],
            &[],
        );
        let switching = card_says_on(&view_with(two), 960.0, Some(ProfileIx(1)));
        assert!(
            switching.contains("Use “work” for this account"),
            "the card offers no way to put the other profile in use: {switching}"
        );
        assert!(
            !switching.contains(copy::profiles::ONE_PROFILE),
            "an account with a switch on screen is told it has nothing to switch between: \
             {switching}"
        );

        let alone = reading_of(&[(ProfileIx::ROOT, Some("home"))], &[]);
        let lonely = card_says(&view_with(alone), 960.0);
        assert!(
            lonely.contains(copy::profiles::ONE_PROFILE),
            "a lone-profile account is left with no control and no explanation, which reads as an \
             app that does not support more than one: {lonely}"
        );

        // And the create control, which is the other half of what was reported missing. Gated on a
        // MEASURED mint availability, so the fixture has to say the node can honour it.
        let capable = TrayView {
            profile_creation: ProfileCreation::Possible,
            ..view_with(reading_of(&[(ProfileIx::ROOT, Some("home"))], &[]))
        };
        assert!(
            card_says(&capable, 960.0).contains(crate::tray_menu::CREATE_PROFILE_LABEL),
            "an account that already holds a profile is offered no way to add another"
        );
    }

    /// **Hiding is never worded as deleting, now that a control one row away really deletes**
    ///   (dig_ecosystem#3037).
    ///
    /// This replaces `no_profile_copy_implies_a_profile_can_be_deleted`, which swept the card for
    /// the word *delete* and was correct only while hiding was all there was. Melting both
    /// singletons ships now, so that sweep would forbid the truthful label on a real control — but
    /// the half it protected is MORE load-bearing than before: with both controls on one card, a
    /// hide row worded as removal is a person ending an identity they meant to tidy away.
    ///
    /// The fixture draws the card in the state where BOTH controls are present, because that is the
    /// only state in which the two can be confused. It holds a VISIBLE non-active profile and a
    /// HIDDEN one, so both arms of the visibility label — *hide* and *show* — are on screen; the
    /// unhide arm is the same copy class and is worded by the same `match`.
    ///
    /// The sweep reads the labels the MODEL built and the card PAINTED, never a literal repeated
    /// here: a test that lowercases a sentence it authored itself asserts nothing about production,
    /// and stays green through any rewording of the row it claims to protect.
    #[test]
    fn hiding_is_never_worded_as_deleting_even_beside_a_real_delete_control() {
        let view = TrayView {
            profile_deletion: crate::profiles::ProfileDeletion::of_seams(
                true,
                Some(&crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            ),
            ..view_with(reading_of(
                &[
                    (ProfileIx::ROOT, Some("home")),
                    (ProfileIx(1), Some("work")),
                    (ProfileIx(2), Some("spare")),
                ],
                &[ProfileIx(2)],
            ))
        };
        // One page per profile, so both arms of the visibility label and the delete label are
        // read from the pages that actually carry them (dig_ecosystem#3069's browser).
        let painted = [ProfileIx::ROOT, ProfileIx(1), ProfileIx(2)]
            .map(|ix| card_says_on(&view, 960.0, Some(ix)))
            .join(" | ");

        let tab = crate::window_model::build(&view)
            .tab(TabId::Account)
            .cloned()
            .expect("the Account tab is emitted in every account state");
        let visibility_labels: Vec<String> = ProfileVerbs::of(&tab)
            .per_profile
            .iter()
            .filter(|action| matches!(action.id, TrayAction::SetProfileVisibility { .. }))
            .map(|action| action.label.clone())
            .collect();
        assert_eq!(
            visibility_labels.len(),
            2,
            "the fixture drew {} visibility control(s), so the sweep below covers neither the hide \
             arm nor the show arm as intended: {painted}",
            visibility_labels.len()
        );

        // The rows' own words plus the note under the list. Scoped to the visibility copy rather
        // than swept over the whole card: the card now legitimately carries a truthful *Delete*
        // label, so a blanket sweep — what the old test did — would forbid correct copy.
        for hide_copy in visibility_labels
            .iter()
            .map(String::as_str)
            .chain([copy::profiles::HIDE_NOTE])
        {
            assert!(
                painted.contains(hide_copy),
                "“{hide_copy}” never reached the screen, so sweeping its words proves nothing about \
                 what a person reads: {painted}"
            );
            let lowered = hide_copy.to_lowercase();
            for forbidden in ["delete", "remove", "erase", "destroy"] {
                assert!(
                    !lowered.contains(forbidden),
                    "the hide copy “{hide_copy}” is worded as removal, one row from a control that \
                     really ends the profile"
                );
            }
        }
        // The control: the delete row IS on this card, so the assertions above are about wording
        // rather than about a card where the confusion cannot arise.
        assert!(
            painted.contains("Delete “work” permanently"),
            "the delete control is absent, so nothing here distinguishes hiding from deleting: \
             {painted}"
        );
    }

    /// **The delete control is drawn for EVERY profile where deletion is measured possible, and for
    /// none where it is not** (dig_ecosystem#3037).
    ///
    /// Both directions, because each catches a different defect. The positive leg catches the
    /// account that holds ONE profile: withholding delete there — the shape *hide* takes, since
    /// dig-account refuses to hide the active profile — would leave that person permanently unable
    /// to delete anything, which is the trap `professional-ui` forbids. So the fixture is a lone
    /// ACTIVE profile, the exact case a per-profile filter would drop.
    ///
    /// The negative leg walks `Unknown` as well as every blocker, because `Unknown` answers
    /// `blocked() == None` exactly as `Possible` does — any gate written against `blocked()` rather
    /// than against the ARM offers an irreversible spend on a build nobody has measured.
    #[test]
    fn the_delete_control_appears_only_where_deletion_is_measured_possible() {
        let alone = reading_of(&[(ProfileIx::ROOT, Some("home"))], &[]);

        let capable = TrayView {
            profile_deletion: crate::profiles::ProfileDeletion::of_seams(
                true,
                Some(&crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            ),
            ..view_with(alone.clone())
        };
        assert!(
            card_says(&capable, 960.0).contains("Delete “home” permanently"),
            "an account with one profile — which cannot switch away and cannot hide it — was left \
             with no way to delete it at all"
        );

        let mut withheld = vec![crate::profiles::ProfileDeletion::Unknown];
        withheld.extend(
            crate::profiles::DeletionBlocked::EVERY.map(crate::profiles::ProfileDeletion::Blocked),
        );
        for deletion in withheld {
            let view = TrayView {
                profile_deletion: deletion,
                ..view_with(alone.clone())
            };
            let painted = card_says(&view, 960.0);
            assert!(
                !painted.contains("Delete “home” permanently"),
                "{deletion:?} drew a control leading to an irreversible spend it cannot honour: \
                 {painted}"
            );
        }
    }

    /// The root fixtures: a real 64-hex value, and the `0x` form the card must print.
    const ANCHORED: &str = "371a39b047420000000000000000000000000000000000000000000000000000";

    /// The card over one profile whose active row carries `root`.
    ///
    /// One profile, deliberately: the sibling-attribution property is the model's and is pinned
    /// there, and a second row here would only make the painted text ambiguous about which row a
    /// hash belongs to.
    fn card_with_root(root: RootReading) -> String {
        let reading = reading_of(&[(ProfileIx::ROOT, None)], &[])
            .with_active_read(root, BodyRepair::Unmeasured);
        card_says(&view_with(reading), 520.0)
    }

    /// **A root read off the chain is shown in full, labelled as what the CHAIN holds.**
    ///
    /// The label is asserted with the value because the two are one claim. A card that printed the
    /// hash under a bare *Root* would be equally true of a root this app merely predicted, and the
    /// whole point of dig-app#212 is that a person can tell those apart without reading the source.
    #[test]
    fn the_card_shows_the_root_the_chain_anchors() {
        let said = card_with_root(RootReading::Anchored(format!("0x{ANCHORED}")));
        assert!(said.contains(copy::profiles::ROOT_LABEL), "{said}");
        assert!(said.contains(&format!("0x{ANCHORED}")), "{said}");
    }

    /// **The root survives the narrow layout, where the copy control stacks under the value.**
    ///
    /// 320 px is below `identity::copyable`'s side-by-side threshold, so the row re-flows there and
    /// a value that only fits beside its control would vanish. Asserted at a real width rather than
    /// trusted, because the committed captures on this display could not be taken at a phone width
    /// and this is the property they would have shown.
    #[test]
    fn the_root_is_still_shown_where_the_row_has_to_stack() {
        let reading = reading_of(&[(ProfileIx::ROOT, None)], &[]).with_active_read(
            RootReading::Anchored(format!("0x{ANCHORED}")),
            BodyRepair::Unmeasured,
        );
        let said = card_says(&view_with(reading), 320.0);
        assert!(said.contains(copy::profiles::ROOT_LABEL), "{said}");
        assert!(said.contains(&format!("0x{ANCHORED}")), "{said}");
    }

    /// **A root nobody has read is drawn as a sentence, never as a hash.**
    ///
    /// The fixture is the state EVERY row starts in, so a card that rendered the field
    /// unconditionally would print an empty identifier or a zero hash here — both of which read as
    /// a real root at a glance and invite a person to copy one.
    ///
    /// The `0x` occurrences are COUNTED rather than asserted absent, because the store id is a
    /// `0x…` value on the same card and always will be: the property is that this state adds no
    /// SECOND hash-shaped thing. A test naming one hash would miss a zero-filled placeholder, which
    /// is the likelier wrong implementation.
    #[test]
    fn a_root_nobody_has_read_is_never_drawn_as_a_hash() {
        let said = card_with_root(RootReading::Pending);
        assert!(said.contains(copy::profiles::ROOT_PENDING), "{said}");
        assert_eq!(said.matches("0x").count(), 1, "{said}");
    }

    /// **A store that has published nothing says so where the root would be.**
    ///
    /// Distinct from the pending sentence on purpose: *not read yet* and *nothing was ever
    /// published* have opposite remedies, and the second must never offer a retry
    /// (dig_ecosystem#3036). Both sentences are asserted so an implementation that collapsed them
    /// into one fails here rather than passing on a contains check.
    #[test]
    fn a_profile_that_has_published_nothing_says_so_where_the_root_would_be() {
        let said = card_with_root(RootReading::Unpublished);
        assert!(said.contains(copy::profiles::ROOT_UNPUBLISHED), "{said}");
        assert!(!said.contains(copy::profiles::ROOT_PENDING), "{said}");
        assert_eq!(said.matches("0x").count(), 1, "{said}");
    }

    /// **A root that could not be read reports the reason it could not be read.**
    ///
    /// The deciding layer's own words, not a generic sentence: the remedy for *your node is not
    /// running* is not the remedy for anything else, and a card that flattened every failure into
    /// one line is the defect `ProfileReading::of_read_failure` exists to prevent, re-committed one
    /// surface later.
    #[test]
    fn a_root_that_could_not_be_read_says_why() {
        let why = "Your node is not answering.";
        let said = card_with_root(RootReading::Unreadable(why.to_string()));
        assert!(said.contains(why), "{said}");
        assert_eq!(said.matches("0x").count(), 1, "{said}");
    }

    /// **The root control is addressed by the profile's index, and never shares the DID's or the
    /// store's id.**
    ///
    /// Three copy controls in one row: egui resolves a duplicate id by refusing one of them, so a
    /// shared namespace here would make a Copy press report the wrong value copied — the failure
    /// `store_element`'s own namespace was introduced for.
    #[test]
    fn each_profiles_root_control_has_its_own_element_id() {
        let rows = reading_of(&[(ProfileIx::ROOT, None), (ProfileIx(1), None)], &[]);
        let rows = rows.rows().expect("a read list").to_vec();
        assert_ne!(root_element(&rows[0]), root_element(&rows[1]));
        assert_ne!(root_element(&rows[0]), did_element(&rows[0]));
        assert_ne!(root_element(&rows[0]), store_element(&rows[0]));
    }

    /// **A DID copy control is addressed by the profile's index, so two rows never share one id.**
    ///
    /// egui reports a duplicate id by refusing one of the two controls, which is a copy button that
    /// silently does nothing — the exact failure `row_element_id`'s occurrence count exists to
    /// prevent one level up.
    #[test]
    fn each_profiles_did_control_has_its_own_element_id() {
        let rows = reading_of(&[(ProfileIx::ROOT, None), (ProfileIx(1), None)], &[]);
        let rows = rows.rows().expect("a read list").to_vec();
        assert_ne!(did_element(&rows[0]), did_element(&rows[1]));
        assert_eq!(did_element(&rows[0]), did_element(&rows[0].clone()));
    }
    /// **The card's cannot-create sentence calls a profile what the row three lines above calls
    /// it.**
    ///
    /// The PLACEMENT half of dig_ecosystem#2981. The copy layer's own test proves the sentence CAN
    /// be named from a list; this proves the card actually hands it the list it drew the rows from.
    /// Without this, a `create_panel` that passed [`ProfileNames::NONE`] — the wrong layer, and the
    /// state this file was in before the fix — leaves the copy test green and still paints two
    /// names for one profile.
    ///
    /// Both names are read back off the rendered card, and both come from
    /// [`ProfileRow::display_name`] rather than from literals, so the row and the sentence are
    /// pinned to ONE derivation. The ordinal forms are asserted ABSENT because an implementation
    /// naming the profile twice — label and number — would satisfy a contains check alone.
    #[test]
    fn the_card_names_a_profile_the_way_its_row_does() {
        let reading = reading_of(
            &[
                (ProfileIx::ROOT, Some("personal")),
                (ProfileIx(1), Some("work")),
            ],
            &[],
        );
        let view = TrayView {
            profile_creation: ProfileCreation::Blocked(CreationBlocked::FundingElsewhere {
                funding: ProfileIx::ROOT,
                target: ProfileIx(1),
            }),
            ..view_with(reading.clone())
        };

        let painted = card_says(&view, 960.0);
        for ix in [ProfileIx::ROOT, ProfileIx(1)] {
            let row_says = reading
                .row(ix)
                .expect("the fixture holds both rows")
                .display_name();
            assert!(
                painted.contains(&row_says),
                "the card explains itself without using {row_says}, the name its own row carries: \
                 {painted}"
            );
        }
        for numbered in ["profile 1", "profile 2"] {
            assert!(
                !painted.contains(numbered),
                "the card numbers a profile it also names, so one profile wears two names on one \
                 screen: {painted}"
            );
        }
    }
}
