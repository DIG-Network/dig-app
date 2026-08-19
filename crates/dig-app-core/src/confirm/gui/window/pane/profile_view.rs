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
                // The tile draws no label of its own — its `name` argument names the TEXTURE — so
                // the heading is drawn here. Without it a reader gets a picture with nothing saying
                // whether it is the profile picture or the header.
                flow.place(|ui, at| (text::caption(ui, at, t, edited.heading()), ()));
                flow.gap(space::S1);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A store id, of the shape every DIG surface prints.
    const ID: &str = "371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0";

    /// The root the user's own profile was anchored at when it was found with no body at all
    /// (dig_ecosystem#3041) — the state this card exists to be honest about.
    const ROOT: &str = "0x371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0";

    /// A 1x1 PNG, as a profile carries one: an RFC 2397 data URL.
    ///
    /// A REAL image rather than a placeholder string, because the property under test is that a
    /// published picture is drawn as a picture — and an undecodable value reaches the same tile by
    /// the "cannot be shown" path, which would make the test pass while showing nothing.
    const PICTURE: &str = concat!(
        "data:image/png;base64,",
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
    );

    /// A held reading publishing `published`.
    fn held_with(published: &[(ProfileField, &str)]) -> ViewedProfile {
        let mut fields = BTreeMap::new();
        for (field, value) in published {
            fields.insert(*field, (*value).to_string());
        }
        ViewedProfile::Held {
            store_id: ID.to_string(),
            root: ROOT.to_string(),
            fields,
        }
    }

    /// Every string the card painted for `reading`, with `typed` in the box.
    ///
    /// Drawn through the REAL card, because the property under test is what a person SEES: a helper
    /// that returned the right sentence would prove nothing about a card drawing empty fields
    /// beside it.
    fn card_says(reading: &ViewedProfile, typed: &str) -> String {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let t = crate::confirm::gui::theme::Theme::Light.tokens();
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::Vec2::new(960.0, 8_000.0));
        ctx.data_mut(|d| d.insert_temp(super::typed_id(), typed.to_string()));

        let mut output = egui::FullOutput::default();
        // Two frames: the first builds the font atlas, the second lays out against it.
        for _ in 0..2 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("profile-view-card-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            let column = egui::Rect::from_min_size(
                                screen.left_top(),
                                egui::Vec2::new(960.0 - space::S5 * 2.0, f32::INFINITY),
                            );
                            let mut flow = Flow::new(ui, column, true);
                            super::card(&mut flow, &t, reading);
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

    /// **An anchored root with no body is never drawn as a profile that publishes nothing.**
    ///
    /// The headline honesty property, and the state a real user's own profile was in
    /// (dig_ecosystem#3041): the chain anchors a root and the node holds `body_b64: NULL`.
    ///
    /// The distinguishing fixture is the NEAREST WRONG rendering — a profile whose content IS held,
    /// verified, and publishes nothing. Both come to "there is nothing to show", so an assertion
    /// that the card is empty would pass on either. What separates them is the claim each makes:
    /// one says the content is missing, the other says the content is present and empty and is
    /// therefore allowed to say it verified. Both directions are asserted, so neither state can
    /// borrow the sentence of the other.
    #[test]
    fn a_root_with_no_body_is_not_drawn_as_a_profile_that_publishes_nothing() {
        let missing = card_says(
            &ViewedProfile::BodyMissing {
                store_id: ID.to_string(),
                root: ROOT.to_string(),
            },
            "",
        );
        assert!(
            missing.contains(copy::profile_view::BODY_MISSING),
            "a profile whose content this node does not hold did not say so: {missing}"
        );
        assert!(
            missing.contains(ROOT),
            "the anchored root was withheld from the one state a person most needs to check: {missing}"
        );
        assert!(
            !missing.contains(copy::profile_view::VERIFIED),
            "content nobody holds was described as verified: {missing}"
        );
        assert!(
            !missing.contains(copy::profile_view::NOTHING_PUBLISHED),
            "a missing body was drawn as a profile that publishes nothing, which is the exact claim dig_ecosystem#3041 was caused by: {missing}"
        );
        for field in ProfileField::ALL {
            assert!(
                !missing.contains(field.heading()),
                "a profile with no content drew the field {}, so a reader sees a profile with blank fields: {missing}",
                field.heading()
            );
        }

        // The control: content that IS held and publishes nothing makes the opposite claim.
        let empty = card_says(&held_with(&[]), "");
        assert!(
            empty.contains(copy::profile_view::NOTHING_PUBLISHED),
            "a verified profile publishing nothing did not say so: {empty}"
        );
        assert!(
            !empty.contains(copy::profile_view::BODY_MISSING),
            "a profile whose content is held was described as missing it: {empty}"
        );
    }

    /// **Each of the states says something only it says.**
    ///
    /// Four states reach this card and three of them mean "nothing to show" — not looked up, no such
    /// profile, and root-without-body. A card that drew any two of them the same way would leave a
    /// person unable to tell "check the id you pasted" from "wait for a peer", which are the two
    /// remedies. The fixture varies ONE thing, the reading, and holds the box empty throughout.
    #[test]
    fn the_states_are_four_different_sentences_and_not_one_shrug() {
        let untouched = card_says(&ViewedProfile::NotLookedUp, "");
        let absent = card_says(
            &ViewedProfile::NoProfile {
                store_id: ID.to_string(),
                why: "the chain has no dig-store with that id".to_string(),
            },
            "",
        );
        let missing = card_says(
            &ViewedProfile::BodyMissing {
                store_id: ID.to_string(),
                root: ROOT.to_string(),
            },
            "",
        );
        let shown = card_says(&held_with(&[(ProfileField::DisplayName, "Ada")]), "");

        assert!(
            !untouched.contains(ID),
            "a card nobody has used yet named a store id, so it claims something about a profile nothing has looked at: {untouched}"
        );
        assert!(
            absent.contains("no profile at that store id"),
            "a store id the chain does not know was not reported as absent: {absent}"
        );
        assert!(
            !absent.contains(copy::profile_view::BODY_MISSING),
            "an absent store was described as a real profile whose content is missing: {absent}"
        );
        assert!(
            missing.contains(copy::profile_view::BODY_MISSING),
            "an anchored root with no body did not say so: {missing}"
        );
        assert!(
            shown.contains("Ada"),
            "the name of a verified profile never reached the screen: {shown}"
        );
        assert!(
            shown.contains(copy::profile_view::VERIFIED),
            "a verified profile did not say what makes it trustworthy: {shown}"
        );
    }

    /// **A verified profile shows its picture, and a profile without one shows no picture slot.**
    ///
    /// The fixture is a REAL PNG, so the tile takes its picture path rather than its "cannot be
    /// shown" path — a placeholder string would reach the same tile and leave the test green over a
    /// square saying the picture is broken. The control publishes a name and NO picture, which is
    /// what makes the absence of an empty picture frame observable.
    #[test]
    fn a_published_picture_is_drawn_and_an_unpublished_one_leaves_no_empty_frame() {
        let with_picture = card_says(
            &held_with(&[
                (ProfileField::DisplayName, "Ada"),
                (ProfileField::Avatar, PICTURE),
            ]),
            "",
        );
        assert!(
            with_picture.contains(ProfileField::Avatar.heading()),
            "a published picture was drawn with nothing saying what it is: {with_picture}"
        );
        assert!(
            !with_picture.contains(super::image_well::UNSHOWABLE_SHORT),
            "a valid PNG was reported as undisplayable, so this test would pass over a broken tile: {with_picture}"
        );

        let without = card_says(&held_with(&[(ProfileField::DisplayName, "Ada")]), "");
        assert!(
            !without.contains(ProfileField::Avatar.heading()),
            "a profile publishing no picture was given an empty picture frame, which reads as a picture that failed to load: {without}"
        );
    }

    /// **Bytes that do not match the anchored root are named, and never rendered.**
    ///
    /// The fixture is the state a hostile or stale node answer produces. The assertion is on what is
    /// ABSENT as much as on what is said: no field heading and no verified claim, because a caveat
    /// beside a rendered profile is a caveat a reader can miss.
    #[test]
    fn content_that_does_not_match_its_root_is_refused_on_screen_not_annotated() {
        let said = card_says(
            &ViewedProfile::Unverifiable {
                store_id: ID.to_string(),
                root: ROOT.to_string(),
                why: "the body is not canonical DPB".to_string(),
            },
            "",
        );
        assert!(
            said.contains("does not match the root"),
            "content that failed verification was not named as such: {said}"
        );
        assert!(
            !said.contains(copy::profile_view::VERIFIED),
            "unverified content was described as verified: {said}"
        );
        for field in ProfileField::ALL {
            assert!(
                !said.contains(field.heading()),
                "unverified content was rendered under {}: {said}",
                field.heading()
            );
        }
    }

    /// **A lookup that could not be made is not reported as a profile that does not exist.**
    ///
    /// The two have opposite remedies, and only one of them is about the store id a person typed.
    #[test]
    fn a_failed_lookup_says_nothing_about_whether_the_profile_exists() {
        let said = card_says(
            &ViewedProfile::Unreachable {
                store_id: ID.to_string(),
                why: "DIG could not reach your node".to_string(),
            },
            "",
        );
        assert!(
            said.contains("could not look this profile up"),
            "a lookup that never happened was not reported as one: {said}"
        );
        assert!(
            !said.contains("no profile at that store id"),
            "an unasked question was reported as an absent profile, sending a person to re-check an id that was correct: {said}"
        );
    }

    /// **A pasted DID is told why it cannot be resolved, not that it is malformed.**
    ///
    /// A DID holder has a DID that is fine; the gap is that nothing indexes a DID back to its store.
    /// Telling them their identifier is wrong sends them to re-copy a correct value.
    #[test]
    fn a_did_is_told_what_is_missing_rather_than_that_it_is_wrong() {
        let did = "did:chia:1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let said = card_says(&ViewedProfile::NotLookedUp, did);
        assert!(
            said.contains(copy::profile_view::DID_NOT_RESOLVABLE),
            "a DID was not told why DIG cannot follow it: {said}"
        );
        assert!(
            !said.contains(&QueryProblem::NotAnId.sentence()),
            "a well-formed DID was reported as gibberish: {said}"
        );
    }

    /// **A truncated store id is corrected at the box, before anything is looked up.**
    #[test]
    fn a_short_paste_is_corrected_under_the_box() {
        let short = &ID[..ID.len() - 1];
        let said = card_says(&ViewedProfile::NotLookedUp, short);
        assert!(
            said.contains(&QueryProblem::WrongLength { len: 63 }.sentence()),
            "a truncated id drew no correction: {said}"
        );
    }
}
