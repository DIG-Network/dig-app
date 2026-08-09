//! The Content tab: how much disk DIG is using, the limit on it, and what is mirrored here.
//!
//! # The trap this pane is designed around
//!
//! The cache can honestly report gigabytes used **and list nothing**. Content arrives in pieces, and
//! a store is only a *capsule* here once it has finished syncing — so "407 MB used" above an empty
//! list is an ordinary state, not a fault. It does not read like one: a person sees a real figure
//! over an empty table and concludes the table is broken. So the empty state is written twice —
//! [`copy::content::CAPSULES_EMPTY_WITH_BYTES`] when the cache holds something, and
//! [`copy::content::CAPSULES_EMPTY`] when it does not — and which one appears is decided from the
//! usage figure rather than from the list alone.
//!
//! # Every figure on this pane is a reading (dig_ecosystem#2397)
//!
//! The meter and the size limit come from the node's `control.status` cache snapshot; the LIST comes
//! from `control.hostedStores.list`, through [`crate::hosted_stores::HostedStoresReading`]. That
//! reading is taken WHOLE rather than as an `Option<Vec<_>>`, and the card matches it exhaustively,
//! because its three states are three different sentences: a read under way is a wait, a node that
//! answered with nothing is an empty list, and a read that failed names the one remedy that fixes
//! it. Collapsed into an `Option`, the first and the last become the same `None` — which is the
//! honesty failure this pane was rebuilt to remove.
//!
//! One thing on this tab is still not wired: **mirroring**. The add-a-store form validates what is
//! typed and cannot ask the node to act on it (dig_ecosystem#2324), and says so in a caption under
//! its own control rather than in a second banner.
//!
//! # The list is legitimately longer than the Home tab's store count
//!
//! `control.hostedStores.list` returns cached ∪ pinned stores — dig-node's `SPEC.md` §7.6 makes a
//! pinned-but-uncached store appearing here a MUST — while `control.status`'s `hosted_store_count`,
//! which Home reports, counts only the stores with content cached. On the live node that is 5 rows
//! against 3. Both are right; the two extra rows say plainly that nothing is cached for them yet,
//! which is what lets a reader reconcile the two numbers by looking rather than by guessing.

use super::action::{self, Action};
use super::card;
use super::copy;
use super::data::{self, Readout, Tone, Value};
use super::facts::PaneFacts;
use super::field;
use super::flow::Flow;
use super::select::{self, Choice};
use super::state::{self, PaneState};
use super::text;
use crate::cache::CacheSnapshot;
use crate::confirm::gui::paint;
use crate::confirm::gui::render::{mono, regular, rgba, size, space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::hosted_stores::{HostedStore, HostedStoresReading};
use crate::tray_menu::TrayAction;
use crate::window_model::Tab;

/// Draw the Cache pane's content into `flow`, and report the action pressed.
pub(crate) fn draw(
    flow: &mut Flow,
    t: &Tokens,
    tab: &Tab,
    facts: &PaneFacts,
) -> Option<TrayAction> {
    usage_card(flow, t, facts.cache);
    flow.gap(space::S4);
    let pressed = limit_card(flow, t, tab, facts.cache);
    flow.gap(space::S4);
    capsules_card(flow, t, &facts.hosted_stores, facts.cache);
    flow.gap(space::S4);
    add_card(flow, t);
    pressed
}

/// How much disk is used, against the limit — or the reason neither figure is known.
fn usage_card(flow: &mut Flow, t: &Tokens, cache: Option<CacheSnapshot>) {
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::content::USAGE_CARD), |inner| {
                inner.place(|ui, at| {
                    let height = match cache {
                        Some(snapshot) => data::meter(
                            ui,
                            at,
                            t,
                            copy::content::METER_LABEL,
                            snapshot.used_bytes,
                            snapshot.cap_bytes,
                        ),
                        // No meter, and deliberately not a meter at zero: an empty bar says the
                        // cache is empty, which is a claim no node has made.
                        None => data::readout(
                            ui,
                            at,
                            t,
                            &Readout::new(
                                copy::content::METER_LABEL,
                                Value::Unknown(copy::content::USAGE_UNKNOWN.to_string()),
                            ),
                        ),
                    };
                    (height, ())
                });
            }),
            (),
        )
    });
}

/// The size limit: a chooser over the presets, the verb that opens a custom one, and the cost.
///
/// # Why a chooser, and why the group had to be taken apart first (dig_ecosystem#2355)
///
/// The limit is a SETTING with one value in force, which is what [`super::select`] exists to say —
/// its own doc names a cache preset as the case it was built for, and the update channel already
/// uses it. Drawn as buttons instead, the card put seven pills across two rows that wrapped to four
/// ragged rows at 480 px, and it mixed three different KINDS of thing into one run of identical
/// controls: six values, one verb, and a help link. A link that navigates looked exactly like a
/// value that selects.
///
/// So the group is partitioned by what each element IS. The presets become choices, `Custom size…`
/// becomes a ghost button beside the chooser because it opens something rather than being something,
/// and the privacy link leaves the control group entirely for the foot of the card.
fn limit_card(
    flow: &mut Flow,
    t: &Tokens,
    tab: &Tab,
    cache: Option<CacheSnapshot>,
) -> Option<TrayAction> {
    let parts = LimitRows::of(tab);
    if parts.is_empty() {
        return None;
    }
    let live = flow.live();
    let options = parts.options();
    let selected = parts.preset_in_force(cache);
    let unknown = parts.unknown_label(cache);

    flow.place(|ui, at| {
        let (height, pressed) =
            card::interactive_card(ui, at, t, live, Some(copy::content::LIMIT_CARD), |inner| {
                let mut hit = None;
                if !options.is_empty() {
                    hit = inner.place(|ui, at| {
                        select::select(
                            ui,
                            at,
                            t,
                            live,
                            &select::Select {
                                label: copy::content::LIMIT_FIELD,
                                options: &options,
                                selected,
                                unknown: &unknown,
                                id: egui::Id::new("dig-cache-size-limit"),
                            },
                        )
                    });
                    inner.gap(space::S3);
                }
                if !parts.verbs.is_empty() {
                    hit = hit
                        .or(inner.place(|ui, at| action::buttons(ui, at, t, live, &parts.verbs)));
                    inner.gap(space::S3);
                }
                inner.place(|ui, at| (text::caption(ui, at, t, copy::content::LIMIT_HINT), ()));
                if !parts.about.is_empty() {
                    inner.gap(space::S3);
                    hit = hit
                        .or(inner.place(|ui, at| action::buttons(ui, at, t, live, &parts.about)));
                }
                hit
            });
        (height, pressed.flatten())
    })
}

/// The limit card's rows, sorted by what each one IS rather than by where it sits.
///
/// Matched on the ACTION, never on the label: the preset labels carry a `— current` marker that
/// moves as the setting changes, and a partition that read the words would re-sort itself the first
/// time one was reworded (`settings::channel_in_force` records the same rule for the channel).
struct LimitRows {
    /// The size presets — the values one of which is in force.
    presets: Vec<Action<TrayAction>>,
    /// The verbs that OPEN something rather than being a value. `Custom size…` today.
    verbs: Vec<Action<TrayAction>>,
    /// The explainer link, which is neither a value nor a verb on this setting.
    ///
    /// Kept as the model's own row rather than written here, and rendered at the foot of the card
    /// away from the control group — where it can no longer be mistaken for a size.
    about: Vec<Action<TrayAction>>,
}

impl LimitRows {
    /// Sort `tab`'s rows, keeping the model's order and its element ids.
    fn of(tab: &Tab) -> Self {
        let mut rows = Self {
            presets: Vec::new(),
            verbs: Vec::new(),
            about: Vec::new(),
        };
        for action in super::actions_of(tab) {
            match action.id {
                TrayAction::SetCacheCap { .. } => rows.presets.push(action),
                TrayAction::SetCustomCacheCap => rows.verbs.push(action),
                // Includes the row the model emits INSTEAD of the presets when no node has been
                // reached — `Change the size limit (connect a node first)…`, which is an explainer
                // wearing a setting's name. It routes to the same place and belongs with the link.
                _ => rows.about.push(action),
            }
        }
        rows
    }

    fn is_empty(&self) -> bool {
        self.presets.is_empty() && self.verbs.is_empty() && self.about.is_empty()
    }

    /// The presets as choices, with the model's labels verbatim — marker included.
    fn options(&self) -> Vec<Choice<TrayAction>> {
        self.presets
            .iter()
            .map(|action| Choice {
                label: action.label.clone(),
                id: action.id,
            })
            .collect()
    }

    /// Which preset the node's own cap matches, or `None` when none of them does.
    ///
    /// Read from the CAP the snapshot reports — the same figure the model builds its `— current`
    /// marker from — rather than by looking for that marker's words. A cap a person set through
    /// `Custom size…` matches no preset, and `None` is the truthful answer there: the chooser then
    /// draws [`unknown_label`](Self::unknown_label) instead of resting on a preset nobody chose.
    fn preset_in_force(&self, cache: Option<CacheSnapshot>) -> Option<usize> {
        let cap = cache?.cap_bytes;
        self.presets.iter().position(
            |action| matches!(action.id, TrayAction::SetCacheCap { bytes } if bytes == cap),
        )
    }

    /// What the closed chooser says when no preset is in force.
    ///
    /// Two different absences, and they must not share a sentence. A node that has reported a cap
    /// this list does not contain HAS a limit, and the honest thing is to state it — so the control
    /// says the real figure rather than "not reported", which would deny a setting that exists. With
    /// no snapshot at all nothing has been read, and that is the one that says so.
    fn unknown_label(&self, cache: Option<CacheSnapshot>) -> String {
        match cache {
            Some(snapshot) => {
                copy::content::limit_custom(&crate::cache::format_cap(snapshot.cap_bytes))
            }
            None => copy::content::LIMIT_UNKNOWN.to_string(),
        }
    }
}

/// What this computer mirrors: the list, the empty state that fits it, or why there is no list.
fn capsules_card(
    flow: &mut Flow,
    t: &Tokens,
    reading: &HostedStoresReading,
    cache: Option<CacheSnapshot>,
) {
    let reading = reading.clone();
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::content::CAPSULES_CARD), |inner| {
                match &reading {
                    HostedStoresReading::Known(stores) => capsules(inner, t, stores, cache),
                    // The card's own state, drawn inside it: the read that failed is THIS card's,
                    // and the tab-level banner above knows nothing about it.
                    other => {
                        inner.place(|ui, at| (state::banner(ui, at, t, &unread(other)), ()));
                    }
                }
            }),
            (),
        )
    });
}

/// The state to draw for a reading that produced no list.
///
/// A wait and a failure are different banners on purpose: [`PaneState::Waiting`] is drawn in the
/// recessed panel and [`PaneState::Unreachable`] in amber, because painting a read that is simply
/// still going in warning colours is how people learn to ignore warning colours.
///
/// `Known` cannot reach here — it has a list to draw — and is mapped to its own empty sentence
/// rather than being made unreachable, because a `panic!` in a paint path is a crash on a frame
/// nobody can reproduce.
fn unread(reading: &HostedStoresReading) -> PaneState {
    match reading {
        HostedStoresReading::Pending => {
            PaneState::Waiting(copy::content::CAPSULES_PENDING.to_string())
        }
        HostedStoresReading::Unknown(why) => {
            PaneState::Unreachable(copy::content::stores_unknown(why))
        }
        HostedStoresReading::Known(_) => {
            PaneState::Empty(copy::content::CAPSULES_EMPTY.to_string())
        }
    }
}

/// The list itself, or the empty state that fits what the cache actually holds.
fn capsules(inner: &mut Flow, t: &Tokens, stores: &[HostedStore], cache: Option<CacheSnapshot>) {
    if stores.is_empty() {
        let sentence = empty_reason(cache);
        inner.place(|ui, at| (text::body(ui, at, t, sentence), ()));
        return;
    }
    for (index, store) in stores.iter().enumerate() {
        if index > 0 {
            inner.gap(space::S3);
        }
        let store = store.clone();
        inner.place(|ui, at| (capsule_row(ui, at, t, &store), ()));
    }
}

/// Which empty state applies: the one that explains a figure the reader can see, or the plain one.
///
/// Decided from the USAGE, not from the list: an empty list beside a real figure is the state that
/// reads as a fault, and it is the only one that needs explaining away.
fn empty_reason(cache: Option<CacheSnapshot>) -> &'static str {
    match cache {
        Some(snapshot) if snapshot.used_bytes > 0 => copy::content::CAPSULES_EMPTY_WITH_BYTES,
        _ => copy::content::CAPSULES_EMPTY,
    }
}

/// One mirrored store: its id in mono, then what it holds with the pinned badge beside it. Returns
/// the height used.
///
/// # Why the badge sits under the id rather than opposite it
///
/// A store id is 64 characters and takes the whole column at 480 px. A badge on the same line would
/// have to be measured first and would take that room from the id, which is the value a person is
/// actually here to read — so the second line carries the qualifiers instead, in reading order.
///
/// # Why the second line is a phrase and not a size
///
/// It was a size. Two of the five stores on the live node are pinned with nothing cached yet, and
/// `Pinned · 0 B` reads as a broken row rather than as the ordinary state of a store whose content
/// has not arrived — see [`copy::content::store_contents`], which is where that is decided.
fn capsule_row(ui: &mut egui::Ui, at: egui::Rect, t: &Tokens, store: &HostedStore) -> f32 {
    let id = text::one_line(
        ui,
        &store.store_id,
        mono(size::SM),
        rgba(t.text),
        at.width(),
    );
    let mut height = id.size().y;
    ui.painter()
        .galley(at.left_top(), id, egui::Color32::PLACEHOLDER);
    height += space::S1;

    let second_line = at.top() + height;
    let mut x = at.left();
    if store.pinned {
        let drawn = data::badge(
            ui,
            egui::Pos2::new(x, second_line),
            t,
            copy::content::PINNED_BADGE,
            Tone::Neutral,
        );
        x = drawn.right() + space::S2;
    }
    let measured = ui.painter().layout(
        copy::content::store_contents(
            store.capsule_count,
            &crate::cache::format_cap(store.total_bytes),
        ),
        regular(size::SM),
        rgba(t.muted),
        (at.right() - x).max(1.0),
    );
    let tail = measured.size().y;
    ui.painter().galley(
        egui::Pos2::new(x, second_line),
        measured,
        egui::Color32::PLACEHOLDER,
    );
    height + tail
}

/// The add-a-store form: a field that validates as you type, and the control it would enable.
///
/// # Why the control is drawn and refused rather than omitted
///
/// This differs from the Wallet tab's missing **Send** on purpose. Sending is a capability the app
/// does not have; mirroring is one the NODE has and this window cannot yet ask for
/// (dig_ecosystem#2324). The form is the finished surface for it, under a caption that says so in its
/// own words — and the validation is real, so the id a person pastes is checked against the same
/// 64-hex rule the link parser applies rather than against a second opinion.
fn add_card(flow: &mut Flow, t: &Tokens) {
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::content::ADD_CARD), |inner| {
                let live = inner.live();
                inner.place(|ui, at| (field(ui, at, t, live), ()));
                inner.gap(space::S2);
                inner.place(|ui, at| (text::caption(ui, at, t, copy::content::ADD_NOT_WIRED), ()));
            }),
            (),
        )
    });
}

/// The store-id field and the control it would enable, through the shared [`super::field`].
///
/// The input, its help line and its inline error come from the shared form vocabulary rather than
/// from a second copy here: a pane that draws its own input gives the product two input styles, and
/// the error-attached-beneath rule is exactly the kind of thing one copy keeps and two copies drift
/// on. Only the refused submit button is local, because no other pane has one.
fn field(ui: &mut egui::Ui, at: egui::Rect, t: &Tokens, live: bool) -> f32 {
    let element = egui::Id::new("dig-window-cache-add-store-id");
    let mut typed: String = ui.ctx().data(|d| d.get_temp(element)).unwrap_or_default();

    let mut y = at.top();
    y += field::text_field(
        ui,
        at,
        t,
        live,
        &field::Field {
            label: copy::content::ADD_FIELD_LABEL,
            placeholder: "",
            help: copy::content::ADD_FIELD_HINT,
            error: problem(&typed),
            id: element.with("edit"),
        },
        &mut typed,
    );
    ui.ctx().data_mut(|d| d.insert_temp(element, typed));
    y += space::S3;

    // Never pressable: the verb behind it does not exist in the model yet. The caption below the
    // button states the absence once, in the place it is about. Drawn so the finished shape of the
    // form is visible, refused so it cannot lie.
    paint::button_at(
        ui,
        egui::Rect::from_min_size(
            egui::Pos2::new(at.left(), y),
            egui::Vec2::new(
                paint::button_width(ui, copy::content::ADD_BUTTON),
                paint::BUTTON_HEIGHT,
            ),
        ),
        element.with("submit"),
        copy::content::ADD_BUTTON,
        Weight::Ghost,
        false,
        t,
    );
    y + paint::BUTTON_HEIGHT - at.top()
}

/// What is wrong with a typed store id, or `None` when there is nothing to say yet.
///
/// An EMPTY field is not an error: complaining before a person has typed anything is a form scolding
/// them for opening it. The rule itself is [`crate::link::is_64_hex`] — the same one the link parser
/// applies, so a store id this form accepts is one a `chia://` link would accept too.
fn problem(typed: &str) -> Option<String> {
    let typed = typed.trim();
    match typed.is_empty() || crate::link::is_64_hex(typed) {
        true => None,
        false => Some(copy::content::add_field_error(typed.chars().count())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{GIB, MIB};
    use crate::hosted_stores::HostedStoresUnknown;

    /// The live node's own list, as `control.hostedStores.list` returns it: five stores, two of them
    /// pinned with nothing cached yet.
    ///
    /// Used as the fixture rather than an invented pair because the two empty rows are the case this
    /// card had to be redesigned around, and a fixture of three healthy stores cannot exhibit it.
    fn live_stores() -> Vec<HostedStore> {
        vec![
            store("a".repeat(64), false, 2, 300 * MIB),
            store("b".repeat(64), true, 1, 107 * MIB),
            store("c".repeat(64), true, 0, 0),
            store("d".repeat(64), false, 0, 0),
            store("e".repeat(64), false, 1, 12 * MIB),
        ]
    }

    fn store(store_id: String, pinned: bool, capsule_count: u64, total_bytes: u64) -> HostedStore {
        HostedStore {
            store_id,
            pinned,
            capsule_count,
            total_bytes,
        }
    }

    /// Every string the list card painted at `width` for `reading`.
    ///
    /// Drawn through the real card rather than through its helpers, because the property under test
    /// is what a person SEES: a helper returning the right state proves nothing about a card that
    /// draws an empty list beside it.
    fn card_says(
        reading: &HostedStoresReading,
        cache: Option<CacheSnapshot>,
        width: f32,
    ) -> String {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let t = crate::confirm::gui::theme::Theme::Light.tokens();
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
                    egui::Area::new(egui::Id::new("capsules-card-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            let column = egui::Rect::from_min_size(
                                screen.left_top(),
                                egui::Vec2::new(width - space::S5 * 2.0, f32::INFINITY),
                            );
                            let mut flow = Flow::new(ui, column, true);
                            capsules_card(&mut flow, &t, reading, cache);
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

    /// **A read still in flight must not be drawn as an empty list** (dig_ecosystem#2397).
    ///
    /// The headline honesty property, and the reason this card takes the whole reading rather than an
    /// `Option<&[_]>`: an `Option` collapses *nobody has answered yet* and *the node holds nothing*
    /// into one `None`, and the second of those is a claim about the reader's computer.
    ///
    /// Asserted from BOTH sides against a cache holding real bytes, because that is the state in
    /// which the two are hardest to tell apart on screen — the meter above says 407 MiB either way.
    /// The empty-list control is what stops this passing on a card that simply never draws a list.
    #[test]
    fn a_store_list_still_being_read_is_not_drawn_as_an_empty_one() {
        let cache = Some(CacheSnapshot {
            cap_bytes: GIB,
            used_bytes: 407 * MIB,
        });

        let pending = card_says(&HostedStoresReading::Pending, cache, 960.0);
        assert!(
            pending.contains(copy::content::CAPSULES_PENDING),
            "a read in flight did not say so: {pending}"
        );
        for claim in [
            copy::content::CAPSULES_EMPTY,
            copy::content::CAPSULES_EMPTY_WITH_BYTES,
        ] {
            assert!(
                !pending.contains(claim),
                "a read that has not answered was drawn as a node holding nothing: {pending}"
            );
        }

        // The control: the node ANSWERED with nothing, which is a different claim and must reach
        // the screen as one.
        let answered = card_says(&HostedStoresReading::Known(Vec::new()), cache, 960.0);
        assert!(
            answered.contains(copy::content::CAPSULES_EMPTY_WITH_BYTES),
            "a node that answered with an empty list did not get the empty state: {answered}"
        );
        assert!(
            !answered.contains(copy::content::CAPSULES_PENDING),
            "an answered read was drawn as one still going: {answered}"
        );
    }

    /// **A list that could not be read is never drawn as a zero, and each reason reaches the screen
    /// with its OWN remedy.**
    ///
    /// Swept over every variant [`HostedStoresUnknown::all`] enumerates rather than a sample, in the
    /// shape `no_two_account_states_share_a_word` uses: a new reason cannot silently inherit
    /// another's sentence, because it would arrive here with no sentence at all.
    ///
    /// The cache deliberately holds bytes, so a card that fell back to the bytes-explaining empty
    /// sentence — which is plausible-looking and wrong — fails rather than reads as ordinary.
    #[test]
    fn every_reason_a_list_is_missing_reaches_the_screen_as_its_own_remedy() {
        let cache = Some(CacheSnapshot {
            cap_bytes: GIB,
            used_bytes: 407 * MIB,
        });

        for why in HostedStoresUnknown::all() {
            let said = card_says(&HostedStoresReading::Unknown(why.clone()), cache, 960.0);
            let sentence = copy::content::stores_unknown(&why);
            assert!(
                said.contains(&sentence),
                "{why:?} did not reach the card as its own sentence. It painted: {said}"
            );
            for claim in [
                copy::content::CAPSULES_EMPTY,
                copy::content::CAPSULES_EMPTY_WITH_BYTES,
                copy::content::CAPSULES_PENDING,
            ] {
                assert!(
                    !said.contains(claim),
                    "{why:?} was drawn as an empty or still-loading list: {said}"
                );
            }
        }
    }

    /// **A store pinned before its content arrived reads as an ordinary state, not as a fault.**
    ///
    /// Two of the live node's five stores are exactly this. The nearest wrong rendering is
    /// `Pinned · 0 B`: every part of it is true, and a reader sees a broken row.
    ///
    /// Drawn through the whole card at BOTH widths, and the fixture keeps three stores that DO hold
    /// content — without them a card that replaced every size with the same phrase would pass.
    #[test]
    fn a_pinned_store_with_nothing_cached_does_not_read_as_a_broken_row() {
        for width in [960.0_f32, 480.0] {
            let said = card_says(&HostedStoresReading::Known(live_stores()), None, width);

            assert!(
                said.contains(&copy::content::store_contents(0, "0 B")),
                "at {width} px a store awaiting its content said nothing about it: {said}"
            );
            assert!(
                !said.contains("0 B"),
                "at {width} px a store with nothing cached reported a measurement of zero, which \
                 reads as a broken row: {said}"
            );
            // The control: the stores that DO hold content still report what they hold.
            assert!(
                said.contains("300 MiB") && said.contains("107 MiB") && said.contains("12 MiB"),
                "at {width} px a real size was lost: {said}"
            );
            assert!(
                said.contains(copy::content::PINNED_BADGE),
                "at {width} px the pinned marker is missing: {said}"
            );
        }
    }

    /// **Every store the node listed is drawn** — the list is not truncated, deduplicated or
    /// filtered by this pane.
    ///
    /// The five ids differ in their first character only, which is enough to tell one row from five
    /// while keeping the fixture the real shape a 64-hex id has.
    #[test]
    fn every_store_the_node_listed_reaches_the_card() {
        let stores = live_stores();
        let said = card_says(&HostedStoresReading::Known(stores.clone()), None, 960.0);
        for store in &stores {
            assert!(
                said.contains(&store.store_id),
                "{} was listed by the node and not drawn: {said}",
                store.store_id
            );
        }
    }

    /// **A cache holding bytes but listing nothing explains the figure the reader can see.**
    ///
    /// This is the pane's whole reason for existing in this shape. The fixture is the live machine's
    /// state — 407 MB used, no capsule finished syncing — and the wrong implementation (one empty
    /// sentence for both cases) passes any test that only checks "an empty list says something". So
    /// both actors are asserted: with bytes, the sentence must account for them; with none, it must
    /// not, because telling someone their empty cache holds real content is its own lie.
    #[test]
    fn an_empty_list_over_a_real_figure_says_why() {
        let with_bytes = empty_reason(Some(CacheSnapshot {
            cap_bytes: 10 * GIB,
            used_bytes: 407 * MIB,
        }));
        let with_nothing = empty_reason(Some(CacheSnapshot {
            cap_bytes: 10 * GIB,
            used_bytes: 0,
        }));
        assert_ne!(
            with_bytes, with_nothing,
            "the same sentence is shown whether or not the cache holds anything, so one of the two \
             readers is being told something untrue"
        );
        assert_eq!(with_bytes, copy::content::CAPSULES_EMPTY_WITH_BYTES);
        assert_eq!(with_nothing, copy::content::CAPSULES_EMPTY);
        // And with no snapshot at all: nothing is known about the disk, so the sentence must not
        // claim there are bytes behind the empty list.
        assert_eq!(empty_reason(None), copy::content::CAPSULES_EMPTY);
    }

    /// **The bytes-explaining sentence actually accounts for the figure rather than merely differing
    /// from its sibling.**
    ///
    /// The test above is satisfied by any two different strings. This one pins the PROPERTY: the
    /// sentence has to say the disk figure is real and say why nothing is listed — otherwise a person
    /// reads a real number over an empty table and goes looking for a fault they do not have.
    #[test]
    fn the_bytes_sentence_affirms_the_figure_and_names_the_reason() {
        let sentence = copy::content::CAPSULES_EMPTY_WITH_BYTES.to_lowercase();
        assert!(
            sentence.contains("real") || sentence.contains("is not wrong"),
            "the sentence never affirms the figure above it: {sentence}"
        );
        assert!(
            sentence.contains("sync"),
            "the sentence never names why a cache with content in it lists nothing: {sentence}"
        );
    }

    /// **A store id is validated against the link parser's rule, from both sides of the bound.**
    ///
    /// 64 hex passes; 63 and 65 fail; a 64-character non-hex string fails. The last case is the one a
    /// length-only check gets wrong, and the two neighbours are what stop a rule that accepts
    /// everything from passing — a validator tested only from below can only confirm itself.
    #[test]
    fn the_field_accepts_exactly_what_a_link_would() {
        let hex = "a".repeat(64);
        assert_eq!(problem(&hex), None);
        assert_eq!(
            problem(&format!(" {hex} ")),
            None,
            "surrounding space is trimmed"
        );
        assert!(problem(&"a".repeat(63)).is_some());
        assert!(problem(&"a".repeat(65)).is_some());
        assert!(
            problem(&"z".repeat(64)).is_some(),
            "a 64-character non-hex value was accepted, so the check is counting rather than reading"
        );
    }

    /// **An untouched field says nothing, and a typed one says how many characters it has.**
    ///
    /// The empty case is the form's manners; the count is what makes the error correctable without
    /// the reader counting the id themselves.
    #[test]
    fn an_empty_field_is_not_an_error_and_a_wrong_one_names_its_length() {
        assert_eq!(problem(""), None);
        assert_eq!(problem("   "), None);
        let short = problem(&"a".repeat(63)).expect("63 hex is refused");
        assert!(
            short.contains("63"),
            "the error does not say how long the value actually is: {short}"
        );
    }

    /// **The pane offers exactly the size-limit verbs the model put on the tab.**
    ///
    /// Against the real `window_model::build` output, with a connected node so the presets are
    /// enabled — a pane that dropped a preset, or added one, fails.
    #[test]
    fn the_pane_offers_the_models_verbs_and_nothing_else() {
        let view = crate::tray_menu::TrayView {
            running: true,
            node_connected: true,
            cache: Some(CacheSnapshot {
                cap_bytes: 10 * GIB,
                used_bytes: 407 * MIB,
            }),
            ..crate::tray_menu::TrayView::default()
        };
        let model = crate::window_model::build(&view);
        let tab = model
            .tabs
            .iter()
            .find(|tab| tab.id == crate::window_model::TabId::Content)
            .expect("the Cache tab exists with a node connected");

        let expected: Vec<(String, bool)> = tab
            .sections
            .iter()
            .flat_map(|section| section.rows.iter())
            .filter_map(|row| match row {
                crate::tray_menu::MenuRow::Action { label, enabled, .. } => {
                    Some((label.clone(), *enabled))
                }
                _ => None,
            })
            .collect();
        let drawn: Vec<(String, bool)> = super::super::actions_of(tab)
            .into_iter()
            .map(|action| (action.label, action.enabled))
            .collect();
        assert_eq!(drawn, expected);
        assert!(
            drawn.len() > 1,
            "the fixture produced too few verbs to tell a filter from an empty tab"
        );
    }

    /// The Cache tab as the real model builds it for `cap`.
    fn cache_tab(cap: u64) -> Tab {
        let view = crate::tray_menu::TrayView {
            running: true,
            node_connected: true,
            cache: Some(CacheSnapshot {
                cap_bytes: cap,
                used_bytes: 407 * MIB,
            }),
            ..crate::tray_menu::TrayView::default()
        };
        crate::window_model::build(&view)
            .tab(crate::window_model::TabId::Content)
            .cloned()
            .expect("the Cache tab exists with a node connected")
    }

    /// **The chooser rests on the preset the model marks as current — for every preset, not one.**
    ///
    /// The property is that the control's selection and the model's `— current` marker name the SAME
    /// option. The fixture drives every preset in turn, because a selection derived from a position
    /// — or from the first option, or from the last — agrees with the marker on exactly one cap and
    /// disagrees everywhere else; a single-cap fixture cannot tell those apart.
    ///
    /// The marker is what the assertion compares against rather than the cap the test fed in. That
    /// is deliberate: the marker is the model's own published answer, so this fails if the pane and
    /// the model ever come to disagree about which limit is in force, which is the only failure that
    /// matters to a reader.
    #[test]
    fn the_chooser_rests_on_the_very_preset_the_model_marks_as_current() {
        for &cap in crate::cache::CACHE_PRESETS.iter() {
            let tab = cache_tab(cap);
            let rows = LimitRows::of(&tab);
            let snapshot = CacheSnapshot {
                cap_bytes: cap,
                used_bytes: 407 * MIB,
            };

            let marked: Vec<usize> = rows
                .presets
                .iter()
                .enumerate()
                .filter(|(_, action)| action.label.contains("— current"))
                .map(|(at, _)| at)
                .collect();
            assert_eq!(
                marked.len(),
                1,
                "the model marked {} presets as current at a {cap}-byte cap, so there is no single \
                 answer for the chooser to agree with",
                marked.len()
            );
            assert_eq!(
                rows.preset_in_force(Some(snapshot)),
                Some(marked[0]),
                "the chooser and the model disagree about which limit is in force at {cap} bytes"
            );
        }
    }

    /// **A cap the presets do not contain is stated, not rounded to a neighbouring preset.**
    ///
    /// The custom-size case, and the honesty rule on a chooser: resting on `1 GiB` because the real
    /// limit is nearest to it would report a setting nobody chose. Three actors — a custom cap, no
    /// snapshot at all, and a genuine preset as the control — because the first two are DIFFERENT
    /// absences and a chooser that said "Not reported" for both would deny a limit the node has
    /// plainly reported.
    #[test]
    fn a_custom_cap_is_named_rather_than_resting_on_the_nearest_preset() {
        let custom = 3 * GIB + 512 * MIB;
        assert!(
            !crate::cache::CACHE_PRESETS.contains(&custom),
            "the fixture's cap is a preset, so it cannot exercise the custom case"
        );
        let snapshot = CacheSnapshot {
            cap_bytes: custom,
            used_bytes: 407 * MIB,
        };
        let rows = LimitRows::of(&cache_tab(custom));

        assert_eq!(
            rows.preset_in_force(Some(snapshot)),
            None,
            "a cap matching no preset was drawn as though a preset were in force"
        );
        let said = rows.unknown_label(Some(snapshot));
        assert!(
            said.contains(&crate::cache::format_cap(custom)),
            "the chooser did not say what the limit actually is: {said}"
        );
        assert_ne!(
            said,
            rows.unknown_label(None),
            "a reported custom limit and an unreported one are shown the same words, so one of the \
             two readers is being told something untrue"
        );
        assert_eq!(rows.unknown_label(None), copy::content::LIMIT_UNKNOWN);

        // The control: a real preset still resolves, so `None` above is a finding rather than a
        // lookup that never matches anything.
        let preset = crate::cache::CACHE_PRESETS[0];
        assert!(LimitRows::of(&cache_tab(preset))
            .preset_in_force(Some(CacheSnapshot {
                cap_bytes: preset,
                used_bytes: 0,
            }))
            .is_some());
    }

    /// **The three kinds of row on this card are told apart, and none is lost.**
    ///
    /// The whole point of #2355: a help link that navigates was drawn identically to a size that
    /// selects. Asserted as a partition — every row the model offered lands in exactly one group —
    /// so a sort that dropped the privacy link to tidy the card fails, as does one that left it
    /// among the values.
    #[test]
    fn each_row_is_sorted_by_what_it_is_and_nothing_is_dropped() {
        let tab = cache_tab(crate::cache::CACHE_PRESETS[0]);
        let rows = LimitRows::of(&tab);

        assert_eq!(
            rows.presets.len(),
            crate::cache::CACHE_PRESETS.len(),
            "a size preset did not reach the chooser"
        );
        assert_eq!(
            rows.verbs.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![TrayAction::SetCustomCacheCap],
            "`Custom size…` is a verb and must sit beside the chooser, not inside it"
        );
        assert_eq!(
            rows.about.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![TrayAction::AboutCache],
            "the privacy link is still inside the control group, where it looks like a size"
        );

        let mut sorted: Vec<TrayAction> = rows
            .presets
            .iter()
            .chain(&rows.verbs)
            .chain(&rows.about)
            .map(|a| a.id)
            .collect();
        let mut offered = tab.actions();
        sorted.sort_by_key(|a| format!("{a:?}"));
        offered.sort_by_key(|a| format!("{a:?}"));
        assert_eq!(sorted, offered, "a verb the model offered reached no group");
    }

    /// **With no node the card offers the model's explainer and no chooser at all.**
    ///
    /// The model emits no presets in this state, and a chooser over an empty list would be a control
    /// with nothing in it. The row it does emit is kept rather than dropped, so the surface still
    /// does something visible (#1800).
    #[test]
    fn an_unread_cache_offers_the_explainer_and_no_chooser() {
        let tab = crate::window_model::build(&crate::tray_menu::TrayView {
            running: true,
            cache: None,
            ..crate::tray_menu::TrayView::default()
        })
        .tab(crate::window_model::TabId::Content)
        .cloned()
        .expect("the Cache tab is emitted with no node");

        let rows = LimitRows::of(&tab);
        assert!(rows.presets.is_empty(), "a preset was offered with no node");
        assert!(rows.options().is_empty());
        assert!(
            !rows.about.is_empty(),
            "the tab offers nothing at all, so a person has no route to the explanation"
        );
    }

    /// **The add form says in its OWN words that it cannot act, and does not borrow a sentence from
    /// the card above it.**
    ///
    /// Mirroring is still unwired (dig_ecosystem#2324) while the list above it is not, so this is the
    /// one place on the tab that has to say a control will do nothing. It says it as a caption under
    /// that control rather than as a second banner: two amber paragraphs on one screen is how a
    /// reader learns to skip amber paragraphs.
    ///
    /// It used to be compared against the retired unwired caveat; the remaining property is that the
    /// sentence is its own — distinct from every other piece of prose this card can draw — and that
    /// it states both halves a person needs, that the button will not act and that the field still
    /// checks what they type.
    #[test]
    fn the_add_form_says_in_its_own_words_that_it_cannot_act() {
        let caption = copy::content::ADD_NOT_WIRED;
        for other in [
            copy::content::CAPSULES_EMPTY,
            copy::content::CAPSULES_EMPTY_WITH_BYTES,
            copy::content::CAPSULES_PENDING,
            copy::content::USAGE_UNKNOWN,
            copy::content::LIMIT_HINT,
        ] {
            assert_ne!(
                caption, other,
                "the form borrowed another part of the tab's prose instead of saying its own thing"
            );
        }

        let sentence = caption.to_lowercase();
        assert!(
            sentence.contains("does nothing") || sentence.contains("cannot"),
            "the form never says the control will not act: {sentence}"
        );
        assert!(
            sentence.contains("check"),
            "the form never says what it DOES do, so the field looks as dead as the button: \
             {sentence}"
        );
    }

    /// **A listed store's size is formatted by the app's one byte formatter.**
    ///
    /// Not a local divisor: the tray, the meter and this row all report the same disk in the same
    /// binary units, and a second formatter here would eventually disagree with the bar directly
    /// above it about the same number.
    #[test]
    fn a_store_row_reports_its_size_in_the_shared_units() {
        let listed = store("b".repeat(64), true, 3, 407 * MIB);
        assert_eq!(
            copy::content::store_contents(
                listed.capsule_count,
                &crate::cache::format_cap(listed.total_bytes)
            ),
            "3 capsules · 407 MiB"
        );
    }
}
