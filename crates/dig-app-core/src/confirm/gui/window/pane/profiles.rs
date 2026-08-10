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
//! That a profile can be deleted. Hiding is a preference about this computer's lists; the DID
//! singleton and the store are permanent on chain. See [`copy::profiles`] for that rule and the
//! assertion that holds it.

use super::action::{self, Action};
use super::card;
use super::copy;
use super::data::{self, Tone, Value};
use super::facts::PaneFacts;
use super::flow::Flow;
use super::identity;
use super::state::{self, PaneState};
use super::text;
use crate::confirm::gui::render::space;
use crate::confirm::gui::theme::Tokens;
use crate::profiles::{ProfileRow, ProfilesReading};
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
                create_panel(inner, t, creation);
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

    let mut pressed = None;
    for (index, profile) in rows.iter().enumerate() {
        if index > 0 {
            flow.gap(space::S3);
        }
        pressed = pressed.or(profile_row(flow, t, profile, verbs));
    }

    flow.gap(space::S3);
    // The caution sits under the whole list rather than beside each switch control: it is one
    // statement about what switching costs, and repeated per row it would be four paragraphs saying
    // one thing. It is drawn only where a switch is actually offered — a lone profile has nothing
    // to switch to, and a warning about an act that cannot be performed is noise.
    if rows.iter().any(|profile| !profile.active) {
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

/// One profile: its name and badges, its DID with a way to lift it off the screen, and its verbs.
///
/// The DID is shown in FULL, wrapped, in the identifier face beside a copy control — the same
/// treatment the DIG ID gets one card up, and for the same reason: nobody transcribes a
/// `did:chia:…` string, and truncating it hides characters the reader has no other way to reach.
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
    let actions = verbs.for_profile(profile);
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
            if actions.is_empty() {
                return None;
            }
            inner.gap(space::S3);
            inner.place(|ui, at| action::buttons(ui, at, t, live, &actions))
        });
        (height, hit.flatten())
    })
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
        };
        for action in section_actions(tab) {
            match action.id {
                TrayAction::SetActiveProfile { .. } | TrayAction::SetProfileVisibility { .. } => {
                    verbs.per_profile.push(action)
                }
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
        TrayAction::SetActiveProfile { ix } | TrayAction::SetProfileVisibility { ix, .. } => {
            Some(ix)
        }
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
fn create_panel(flow: &mut Flow, t: &Tokens, creation: crate::profiles::ProfileCreation) {
    let sentence = copy::profiles::cannot_create(creation);
    flow.place(|ui, at| {
        (
            card::panel(ui, at, t, Some(copy::profiles::CREATE_PANEL), |inner| {
                inner.place(|ui, at| (text::body(ui, at, t, sentence), ()));
            }),
            (),
        )
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::profile_session::test_support::{expected_did, session_with};
    use crate::profiles::{ProfileCreation, ProfilesReading, ProfilesUnknown};
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
        let tab = crate::window_model::build(view)
            .tab(TabId::Account)
            .cloned()
            .expect("the Account tab is emitted in every account state");
        let facts = PaneFacts::of_tray(view);

        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let t = crate::confirm::gui::theme::Theme::Light.tokens();
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::Vec2::new(width, 8_000.0));

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

    /// **Every profile reaches the card — hidden ones included — with its own DID and its own
    /// badges.**
    ///
    /// The fixture hides the MIDDLE profile of three and leaves the outer two shown, so a card that
    /// dropped hidden rows loses exactly one, and one that badged every row identically disagrees at
    /// two of the three. A fixture hiding all or none could tell neither apart.
    ///
    /// Asserted at BOTH widths the window spans, because the badge row and the copy control both
    /// reflow at the narrow one.
    #[test]
    fn every_profile_reaches_the_card_with_its_own_did_and_badges() {
        let reading = reading_of(
            &[
                (ProfileIx::ROOT, Some("home")),
                (ProfileIx(1), Some("work")),
                (ProfileIx(2), None),
            ],
            &[ProfileIx(1)],
        );

        for width in [960.0_f32, 480.0] {
            let said = card_says(&view_with(reading.clone()), width);
            for ix in [ProfileIx::ROOT, ProfileIx(1), ProfileIx(2)] {
                assert!(
                    said.contains(&expected_did(ix)),
                    "at {width} px profile {ix} is in the registry and not on the card: {said}"
                );
            }
            assert!(
                said.contains(copy::profiles::ACTIVE_BADGE),
                "at {width} px nothing on the card says which profile is in use: {said}"
            );
            assert!(
                said.contains(copy::profiles::HIDDEN_BADGE),
                "at {width} px a hidden profile is listed without saying it is hidden, so the \
                 control beside it reads as hiding something already visible: {said}"
            );
            assert!(
                said.contains("“home”") && said.contains("“work”"),
                "at {width} px a profile's own name did not reach its row: {said}"
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

    /// **Nothing on this card offers to create a profile, and the reason is stated.**
    ///
    /// The structural half is the one that matters: there is no `CreateProfile` action to draw, so
    /// this cannot be flipped on by a mistaken `enabled: true`. What is asserted here is the half a
    /// person reads — that the absence is explained rather than left as a missing button.
    ///
    /// Both `ProfileCreation` values are drawn, because the two missing pieces need different
    /// sentences and a card that showed one of them for both would send half its readers after the
    /// wrong fault.
    #[test]
    fn the_card_explains_why_it_offers_no_way_to_create_a_profile() {
        let mut said = Vec::new();
        for creation in [
            ProfileCreation::NoChainTransport,
            ProfileCreation::NoProfileMinter,
        ] {
            let view = TrayView {
                profile_creation: creation,
                ..view_with(ProfilesReading::Known(Vec::new()))
            };
            let painted = card_says(&view, 960.0);
            assert!(
                painted.contains(copy::profiles::cannot_create(creation)),
                "{creation:?} did not reach the card as its own sentence: {painted}"
            );
            said.push(copy::profiles::cannot_create(creation));
        }
        assert_ne!(
            said[0], said[1],
            "both missing pieces are explained in the same words, so one reader is sent after a \
             fault they do not have"
        );

        for sentence in &said {
            let lowered = sentence.to_lowercase();
            assert!(
                lowered.contains("not available in this version"),
                "the #1820 wording is missing, so the absence reads as a defect: {lowered}"
            );
            assert!(
                lowered.contains("required"),
                "a profile is described as something a person chose to go without: {lowered}"
            );
            assert!(
                !lowered.contains("optional"),
                "the word #1820 settled against is back: {lowered}"
            );
        }
    }

    /// **No profile copy implies a profile can be deleted.**
    ///
    /// The card's whole risk. Hiding is a preference about one computer's lists; the DID singleton
    /// and the store are permanent on chain, so a person who believed they had deleted an identity
    /// would be wrong about something anyone can still resolve.
    ///
    /// Swept over every sentence this module can paint, including the row LABELS the model builds —
    /// which is where the word would most naturally appear, because a label is short and "remove" is
    /// shorter than "hide from this list".
    #[test]
    fn no_profile_copy_implies_a_profile_can_be_deleted() {
        let reading = reading_of(
            &[
                (ProfileIx::ROOT, Some("home")),
                (ProfileIx(1), Some("work")),
            ],
            &[],
        );
        let view = view_with(reading);
        let painted = card_says(&view, 960.0).to_lowercase();

        for forbidden in ["delete", "remove", "erase", "destroy", "permanently hide"] {
            assert!(
                !painted.contains(forbidden),
                "the profiles card says “{forbidden}”, which claims an act the chain would not \
                 honour: {painted}"
            );
        }
        // The control: it DOES say what hiding actually is, so the sweep above is passing on copy
        // that explains rather than on a card that says nothing.
        assert!(
            painted.contains("stays on the blockchain"),
            "the card never says a hidden profile is still on chain: {painted}"
        );
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
}
