//! The Account tab's **look up a profile** card: somebody ELSE'S profile, rendered from the chain.
//!
//! # Why this card is here and not beside the profiles list
//!
//! [`super::profiles`] answers *which identities does this account hold*. This answers *what does
//! that store publish*, about a person this machine has no key for and no anchor on disk for. They
//! share a tab because both are about identity, and they share nothing else: nothing on this card
//! spends, signs, or edits.
//!
//! # The four states, and the one that is the point
//!
//! A profile is a root the chain anchors plus the bytes that root commits to, kept in different
//! places and independently present. The card must therefore distinguish *nobody has looked yet*,
//! *there is no such profile*, **the root is anchored and the content is not held**, and *the
//! content is held and verified* — and it must never draw the third as the fourth with empty
//! fields. A real user's own profile sat in that third state with an anchored root and a null body,
//! and the app implying all was well is what dig_ecosystem#3041 exists to record.
//!
//! Two further states earn their own sentences for the same reason: *the chain could not be asked*
//! is not an absent profile (retrying can change it, and it says nothing about the store id), and
//! *the held bytes do not rebuild to the anchored root* is not content to display with a caveat —
//! a caveat is a thing a reader can miss, so those bytes are named and dropped.
//!
//! # Nothing here draws a profile a second way
//!
//! The picture is [`super::image_well`]'s tile, the same one the editor draws, and the fields are
//! [`ProfileField`]'s own — `professional-ui`'s reuse rule, which a surface in this repo has already
//! had to be redone for.

use super::action::{self, Action};
use super::card;
use super::copy;
use super::data::{self, Readout, Value};
use super::field::{self, Field};
use super::flow::Flow;
use super::identity;
use super::image_well::{self, Well};
use super::state::{self, PaneState};
use super::text;
use crate::confirm::gui::render::space;
use crate::confirm::gui::theme::Tokens;
use crate::profile_edit::{FieldKind, ProfileField};
use crate::profile_view::{LookupService, ProfileQuery, QueryProblem, ViewedProfile};

/// A control this card owns, as opposed to a verb the model decided.
///
/// Looking a profile up reads the chain and this node; it spends nothing, changes nothing and is
/// available whenever a store id has been typed. That makes it a presentation affordance in
/// [`super::identity::copyable`]'s sense rather than something [`crate::window_model`] should be
/// asked about — there is no state of the machine in which the model would withhold it and this card
/// would still be drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Press {
    /// Start a lookup for what is typed.
    LookUp,
    /// Put the card back to the state it opened in.
    Clear,
}

/// Draw the look-up card into `flow`, showing `reading`.
///
/// The reading is a PARAMETER rather than read from [`LookupService::app`] here, so a test can put
/// the card into any of its states — including the two that are hardest to arrange against a real
/// chain, an anchored root with no body and bytes that do not verify.
pub(crate) fn card(flow: &mut Flow, t: &Tokens, reading: &ViewedProfile) {
    let live = flow.live();
    let reading = reading.clone();

    let pressed = flow.place(|ui, at| {
        let (height, pressed) = card::interactive_card(
            ui,
            at,
            t,
            live,
            Some(copy::profile_view::CARD),
            |inner| {
                inner.place(|ui, at| (text::body(ui, at, t, copy::profile_view::INVITATION), ()));
                inner.gap(space::S3);
                let typed = ask(inner, t);
                inner.gap(space::S3);
                let pressed = controls(inner, t, &typed, &reading);
                inner.gap(space::S4);
                answer(inner, t, &typed, &reading);
                pressed
            },
        );
        (height, pressed.flatten())
    });

    act(pressed, flow);
}

/// Do what was pressed, and ask for a repaint so the answer is not waiting on a mouse move.
fn act(pressed: Option<Press>, flow: &mut Flow) {
    let Some(press) = pressed else {
        return;
    };
    let service = LookupService::app();
    match press {
        // A lookup runs for a store id and nothing else. A DID reaching here would be a control
        // offered over a query that cannot be resolved, which `controls` does not do.
        Press::LookUp => {
            let typed = flow.place(|ui, _| (0.0, load_typed(ui)));
            if let Some(store_id) = ProfileQuery::of(&typed).ok().and_then(|q| q.store_id().map(str::to_owned)) {
                service.look_up(&store_id);
            }
        }
        Press::Clear => {
            service.clear();
            flow.place(|ui, _| (0.0, store_typed(ui, String::new())));
        }
    }
    flow.place(|ui, _| (0.0, ui.ctx().request_repaint()));
}

/// The box a store id is pasted into, and what is wrong with what is in it.
///
/// Returns what is currently typed, so the controls beneath can be decided from the same value the
/// reader is looking at rather than from one read a frame earlier.
fn ask(flow: &mut Flow, t: &Tokens) -> String {
    let live = flow.live();
    let mut typed = flow.place(|ui, _| (0.0, load_typed(ui)));

    // An untouched box is not a mistake, so its problem is not drawn as one: `Empty` is the state
    // the card opens in and the invitation above already says what to do about it.
    let error = match ProfileQuery::of(&typed) {
        Ok(_) | Err(QueryProblem::Empty) => None,
        Err(problem) => Some(problem.sentence()),
    };

    let field = Field {
        label: copy::profile_view::FIELD_LABEL,
        placeholder: copy::profile_view::FIELD_PLACEHOLDER,
        help: copy::profile_view::FIELD_HELP,
        error,
        id: egui::Id::new("dig-profile-view-store-id"),
    };
    flow.place(|ui, at| {
        let height = field::text_field(ui, at, t, live, &field, &mut typed);
        store_typed(ui, typed.clone());
        (height, ())
    });
    typed
}

/// The verbs: look up what is typed, and clear whatever is shown.
///
/// **Clear exists whenever there is something to clear**, which is `professional-ui`'s never-trap
/// rule applied to a card that can end up showing a stranger's profile after one wrong paste.
fn controls(flow: &mut Flow, t: &Tokens, typed: &str, reading: &ViewedProfile) -> Option<Press> {
    let live = flow.live();
    let resolvable = matches!(ProfileQuery::of(typed), Ok(ProfileQuery::Store(_)));

    let mut verbs = vec![Action {
        weight: action::weigh(false),
        element: egui::Id::new("dig-profile-view-look-up"),
        label: copy::profile_view::LOOK_UP.to_string(),
        // Disabled rather than absent: a control that appears when a value becomes valid is a
        // control a person cannot find while they are looking for what to do next.
        enabled: resolvable && !reading.is_looking(),
        id: Press::LookUp,
    }];
    if !matches!(reading, ViewedProfile::NotLookedUp) || !typed.is_empty() {
        verbs.push(Action {
            weight: action::weigh(false),
            element: egui::Id::new("dig-profile-view-clear"),
            label: copy::profile_view::CLEAR.to_string(),
            enabled: true,
            id: Press::Clear,
        });
    }
    flow.place(|ui, at| action::buttons(ui, at, t, live, &verbs))
}

/// Everything below the controls: what the chain and the node said.
fn answer(flow: &mut Flow, t: &Tokens, typed: &str, reading: &ViewedProfile) {
    // A DID is refused by the QUERY, before any lookup, so it is said here rather than as a reading
    // — there is no chain read to report on, and reporting one would be a fiction.
    if matches!(ProfileQuery::of(typed), Ok(ProfileQuery::Did(_))) {
        banner(
            flow,
            t,
            PaneState::Empty(copy::profile_view::DID_NOT_RESOLVABLE.to_string()),
        );
        return;
    }

    match reading {
        // Nothing has been asked, so nothing is claimed. The invitation is the whole content.
        ViewedProfile::NotLookedUp => {}
        ViewedProfile::Looking { store_id } => {
            banner(flow, t, PaneState::Waiting(copy::profile_view::LOOKING.to_string()));
            flow.gap(space::S3);
            store_row(flow, t, store_id);
        }
        ViewedProfile::NoProfile { store_id, why } => {
            banner(flow, t, PaneState::Empty(copy::profile_view::no_profile(why)));
            flow.gap(space::S3);
            store_row(flow, t, store_id);
        }
        ViewedProfile::BodyMissing { store_id, root } => {
            banner(
                flow,
                t,
                PaneState::Empty(copy::profile_view::BODY_MISSING.to_string()),
            );
            flow.gap(space::S3);
            store_row(flow, t, store_id);
            flow.gap(space::S2);
            root_row(flow, t, root);
        }
        ViewedProfile::Unverifiable {
            store_id,
            root,
            why,
        } => {
            banner(
                flow,
                t,
                PaneState::Unreachable(copy::profile_view::unverifiable(why)),
            );
            flow.gap(space::S3);
            store_row(flow, t, store_id);
            flow.gap(space::S2);
            root_row(flow, t, root);
        }
        ViewedProfile::Unreachable { store_id, why } => {
            banner(
                flow,
                t,
                PaneState::Unreachable(copy::profile_view::unreachable(why)),
            );
            flow.gap(space::S3);
            store_row(flow, t, store_id);
        }
        ViewedProfile::Held {
            store_id,
            root,
            fields,
        } => held(flow, t, store_id, root, fields),
    }
}

/// A verified profile: its pictures, its fields, and the two values that prove which one it is.
fn held(
    flow: &mut Flow,
    t: &Tokens,
    store_id: &str,
    root: &str,
    fields: &std::collections::BTreeMap<ProfileField, String>,
) {
    let live = flow.live();
    if fields.is_empty() {
        banner(
            flow,
            t,
            PaneState::Empty(copy::profile_view::NOTHING_PUBLISHED.to_string()),
        );
        flow.gap(space::S3);
    }

    for edited in ProfileField::ALL {
        match edited.kind() {
            // A picture the profile does not publish is drawn as nothing at all: an empty well
            // under "Profile picture" is a slot a reader would take for a broken image.
            FieldKind::Image => {
                let Some(value) = fields.get(&edited) else {
                    continue;
                };
                flow.place(|ui, at| {
                    (
                        image_well::tile(ui, at, t, &Well::of(value, false), edited.heading()),
                        (),
                    )
                });
                flow.gap(space::S3);
            }
            FieldKind::Address => {
                let value = shown(fields.get(&edited));
                flow.place(|ui, at| {
                    (
                        identity::copyable(
                            ui,
                            at,
                            t,
                            edited.heading(),
                            &value,
                            egui::Id::new(("dig-profile-view-field", edited.heading())),
                            live,
                        ),
                        (),
                    )
                });
                flow.gap(space::S2);
            }
            FieldKind::Line | FieldKind::Paragraph => {
                let value = shown(fields.get(&edited));
                flow.place(|ui, at| {
                    (
                        data::readout(ui, at, t, &Readout::new(edited.heading(), value)),
                        (),
                    )
                });
                flow.gap(space::S2);
            }
        }
    }

    flow.gap(space::S2);
    store_row(flow, t, store_id);
    flow.gap(space::S2);
    root_row(flow, t, root);
    flow.gap(space::S2);
    flow.place(|ui, at| (text::caption(ui, at, t, copy::profile_view::VERIFIED), ()));
}

/// A published value, or the honest absence of one.
///
/// A field the body does not carry is [`Value::Unknown`] rather than an empty string: "not
/// published" and "published as empty" read differently to somebody deciding whether they have found
/// the right person, and only one of them is true.
fn shown(published: Option<&String>) -> Value {
    match published {
        Some(text) => Value::Word(text.clone()),
        None => Value::Unknown(copy::profile_view::FIELD_NOT_PUBLISHED.to_string()),
    }
}

/// The state banner, in the card rather than at the top of the tab.
fn banner(flow: &mut Flow, t: &Tokens, shown: PaneState) {
    flow.place(|ui, at| (state::banner(ui, at, t, &shown), ()));
}

/// The store id a reading is about, copyable — it is the value a person carries elsewhere.
fn store_row(flow: &mut Flow, t: &Tokens, store_id: &str) {
    let value = Value::Identifier(store_id.to_string());
    let live = flow.live();
    flow.place(|ui, at| {
        (
            identity::copyable(
                ui,
                at,
                t,
                copy::profile_view::STORE_LABEL,
                &value,
                egui::Id::new("dig-profile-view-store-row"),
                live,
            ),
            (),
        )
    });
}

/// The chain-anchored root.
///
/// Drawn for the two states a person most needs to CHECK — an anchored root with no body, and bytes
/// that do not match it — because the root is the only value with which the claim can be checked at
/// all, and a generic sentence without it is the reassuring one dig_ecosystem#3041 was caused by.
fn root_row(flow: &mut Flow, t: &Tokens, root: &str) {
    let value = Value::Identifier(root.to_string());
    let live = flow.live();
    flow.place(|ui, at| {
        (
            identity::copyable(
                ui,
                at,
                t,
                copy::profile_view::ROOT_LABEL,
                &value,
                egui::Id::new("dig-profile-view-root-row"),
                live,
            ),
            (),
        )
    });
}

/// The id the typed store id is kept under, for the life of the window.
fn typed_id() -> egui::Id {
    egui::Id::new("dig-profile-view-typed")
}

/// What is currently in the box, or an empty box the first time it is drawn.
fn load_typed(ui: &egui::Ui) -> String {
    ui.data(|d| d.get_temp::<String>(typed_id()))
        .unwrap_or_default()
}

/// Keep the typed value for the next frame.
fn store_typed(ui: &egui::Ui, typed: String) {
    ui.data_mut(|d| d.insert_temp(typed_id(), typed));
}
