//! The content-pane design system: the vocabulary a tab's content is written in.
//!
//! # The problem this exists to solve
//!
//! Content panes used to render `Vec<MenuRow>` — the tray menu's own row type — whose entire
//! vocabulary is *separator, labelled action, submenu*. A pane could not look like an application
//! because it had no words for one, so every tab read as a menu inside a window
//! (dig_ecosystem#2326).
//!
//! # The line this system does not cross
//!
//! **The rules stay single-sourced; the presentation vocabulary gets richer.** Which verbs exist and
//! whether each is enabled is decided ONCE, by the group builders in [`crate::tray_menu`], composed
//! into tabs by [`crate::window_model`]. This layer may render a decided verb as a prominent primary
//! button with supporting copy where the tray renders it as a row. It may not decide for itself
//! whether that verb is offered.
//!
//! The check, when writing a pane: if you find yourself asking *"should this be shown?"*, the model
//! already answered — go read its answer. Facts a pane may display are projected into
//! [`facts::PaneFacts`], which deliberately holds no enablement to re-derive.
//!
//! # The vocabulary
//!
//! | Module | What it is for | When NOT to use it |
//! |---|---|---|
//! | [`flow`] | The vertical cursor blocks are placed through | Never place a block by computing a `y` yourself |
//! | [`text`] | Four prose roles: title, heading, body, caption | Anything that is a value — that is [`data`] |
//! | [`card`] | Grouping related facts under a title | A single self-describing thing; three levels of nesting |
//! | [`data`] | Readouts, measures, meters, badges | Prose; an unbounded count in a meter |
//! | [`action`] | Verbs, with primary/ghost/danger weight | Anything not decided by the model |
//! | [`state`] | The four async states, banner-drawn | A success banner — success shows itself |
//! | [`identity`] | Values a person takes elsewhere: copy, QR | A value nobody transcribes |
//! | [`copy`] | Every string, named | A literal inside a paint call |
//! | [`facts`] | The readings a pane may display | Anything that decides a verb |
//!
//! # One module per tab — the Phase-2 layout
//!
//! A tab that has been designed gets its OWN module beside [`status`] — `account.rs`, `wallet.rs`,
//! `cache.rs` — exposing one `draw(&mut Flow, &Tokens, &Tab, &PaneFacts) -> Option<TrayAction>`,
//! and one arm in [`draw_tab`]'s match. That is deliberate: tab lanes run in parallel, and this way
//! two of them never write the same file. The one shared line each lane adds is its match arm.
//!
//! Every tab now has one, and [`draw_tab`]'s match is EXHAUSTIVE — there is no catch-all falling
//! back to a generic renderer. That is deliberate: a generic pane was the right floor while tabs
//! were being converted one at a time, and once none are left it is a way for a new tab to ship
//! looking like a menu without anybody deciding it should.
//!
//! # The scales
//!
//! Nothing here picks a pixel or a hex value. Spacing is `render::space` (hub's `--space-*`, a 4 px
//! rhythm), type is `render::size` (hub's `--text-*`), radii are `render::radius`, and every colour
//! comes from [`super::super::theme::Tokens`], which is the hub design system ported once.
//!
//! **[`Tokens`](super::super::theme::Tokens) is EXTENDED, not superseded.** It is a field-by-field
//! mirror of `hub.dig.net`'s CSS custom properties, kept that way so the two copies can be diffed by
//! eye — a pane-specific palette would break that and give the product two looks. What this layer
//! adds on top is *roles*: [`data::Tone`] asks for a meaning ("bad") rather than a colour ("amber"),
//! so the meaning-to-token mapping lives in one place instead of at every call site.
//!
//! # Honesty
//!
//! A card must never imply a fact it does not have. Two things make that the EASY path rather than a
//! review checklist: an absent figure has a first-class spelling, [`data::Value::Unknown`], which
//! carries the sentence saying WHY it is absent; and the reading types a pane draws from —
//! [`crate::hosted_stores::HostedStoresReading`], [`crate::wallet::overview::BalanceReading`],
//! [`crate::apps::AppPresence`] — separate *a read is under way* from *the answer is nothing* from
//! *nobody could ask*, so there is no path that turns an unknown into a zero.
//!
//! There was a fifth pane state, `Unwired`, for cards designed ahead of their plumbing. Both of the
//! surfaces that used it are wired now (dig_ecosystem#2397), and a state nothing can legitimately
//! reach is a banner a pane can still opt into wrongly — so it was removed rather than kept for a
//! future skeleton. A future skeleton should reach for the honest absence of the reading it is
//! waiting on, which says something true about the machine rather than about this project.
//!
//! Neither is a guarantee. `Value::Word("0")` still compiles — see [`data`] for exactly what is and
//! is not enforced, and dig_ecosystem#2337 for making a placeholder unexpressible. A pane still has
//! to be written honestly; this vocabulary means it does not have to be written carefully.

pub(crate) mod account;
pub(crate) mod action;
pub(crate) mod activity;
pub(crate) mod apps;
pub(crate) mod card;
pub(crate) mod content;
pub(crate) mod copy;
pub(crate) mod data;
pub(crate) mod facts;
pub(crate) mod field;
pub(crate) mod fieldset;
pub(crate) mod flow;
pub(crate) mod home;
pub(crate) mod identity;
pub(crate) mod image_pick;
pub(crate) mod image_well;
pub(crate) mod offer_file;
pub(crate) mod profile_edit;
pub(crate) mod profile_form;
pub(crate) mod profile_view;
pub(crate) mod profiles;
pub(crate) mod select;
pub(crate) mod selectable;
pub(crate) mod settings;
pub(crate) mod state;
pub(crate) mod table;
pub(crate) mod text;
pub(crate) mod wallet;
pub(crate) mod wallet_coins;
pub(crate) mod wallet_make_offer;
pub(crate) mod wallet_offer;

use egui::{Rect, Ui};

use super::super::render::space;
use super::super::theme::Tokens;
use crate::tray_menu::{MenuRow, TrayAction};
use crate::window_model::{Tab, TabId};
use facts::PaneFacts;
use flow::Flow;
use state::PaneState;

/// A row's element id: its label, plus which occurrence of that label this is on the tab.
///
/// # Why the label, and not the action or the position
///
/// Not the ACTION, because several actions render two rows each (dig_ecosystem#2257) — an action
/// alone cannot address one row. Not the pixel POSITION, for the reason dig_ecosystem#2074 records:
/// this pane rebuilds every frame and rows above it change height as text rewraps, so a `y` in the
/// id would be a generated id wearing a stable name, replaced under a user mid-click.
///
/// The count of PRECEDING rows with the same label is stable for a given model — it is a position in
/// a list, not a position on screen — which is what separates the Account tab's two
/// `About on-chain DIDs…` rows without reintroducing that hazard.
pub(crate) fn row_element_id(label: &str, occurrence: usize) -> egui::Id {
    egui::Id::new(("dig-window-row", label, occurrence))
}

/// Draw a tab's content into `at`, and report the verb pressed.
///
/// Status has a bespoke pane; every other tab renders through the generic one, which is itself
/// written in this vocabulary — so a tab that has not been designed yet still looks like the rest of
/// the application rather than like a menu.
///
/// # Every pane opens the same way (dig_ecosystem#2356)
///
/// The title, the lead sentence and the state banner are drawn HERE, by the frame, for every tab.
/// The lead used to be optional and two of the seven panes remembered to add one, so five of them
/// opened with a bare word floating above a card and a person arriving at a tab got no orientation.
/// Making it structural is what stops that being a thing a pane can forget: [`copy::lead`] is an
/// exhaustive match, so a new tab has to write its sentence in order to compile.
pub(crate) fn draw_tab(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    tab: &Tab,
    facts: &PaneFacts,
    selected_wallet: crate::window_model::SelectedWallet,
    live: bool,
) -> (f32, Option<super::panes::Click>) {
    let mut flow = Flow::new(ui, at, live);

    flow.place(|ui, at| (text::title(ui, at, t, &tab.label), ()));
    flow.gap(space::S2);
    flow.place(|ui, at| (text::body(ui, at, t, copy::lead(tab.id)), ()));
    flow.gap(space::S4);

    let state = PaneState::of_note(&tab.note);
    if !state.is_silent() {
        flow.place(|ui, at| (state::banner(ui, at, t, &state), ()));
        flow.gap(space::S4);
    }

    // Exhaustive, with no catch-all: every tab has a pane written for its own content, so a new
    // tab must be given one rather than falling silently to [`generic`] — which is a floor for a
    // tab under construction, not a destination a shipping tab should reach by omission.
    //
    // Most panes only ever produce a VERB, so they return a `TrayAction` and it is wrapped here.
    // The Wallet pane also produces a NAVIGATION — its funding control moves the person to the
    // other wallet (dig-app#341) — which no `TrayAction` can express, so that one pane reports the
    // richer type directly. Widening every pane's signature to match would have added a variant
    // none of them can produce.
    let pressed = match tab.id {
        TabId::Home => home::draw(&mut flow, t, tab, facts).map(super::panes::Click::Act),
        TabId::Account => account::draw(&mut flow, t, tab, facts).map(super::panes::Click::Act),
        TabId::Wallet => wallet::draw(&mut flow, t, tab, facts, selected_wallet),
        TabId::Activity => activity::draw(&mut flow, t, tab, facts).map(super::panes::Click::Act),
        TabId::Content => content::draw(&mut flow, t, tab, facts).map(super::panes::Click::Act),
        TabId::Settings => settings::draw(&mut flow, t, tab, facts).map(super::panes::Click::Act),
    };
    (flow.cursor() - at.top(), pressed)
}

/// The verbs in a run of rows, as weighted actions, in the model's order.
///
/// # Why `seen` is a parameter and not a local
///
/// The occurrence count that makes an element id unique must be counted across the WHOLE TAB, not
/// per section: the Account tab's two `About on-chain DIDs…` rows sit in different sections, and a
/// per-section counter gives both occurrence zero — which egui reports as a duplicate id and which
/// leaves one of the two rows unclickable. So the caller owns the counter and threads it through
/// every section of one tab.
///
/// # Why this is the only place a pane derives a row's identity
///
/// It was not, briefly, and that cost a working control: the Status pane grew its own copy that
/// used the row's INDEX where this uses its occurrence, so `Open the log folder` — the second verb
/// on the tab, and the first with that label — was addressed as occurrence 1 while every other
/// caller looked for occurrence 0. Two derivations of one identity is a bug with a delay on it.
pub(crate) fn actions_in(
    rows: impl IntoIterator<Item = MenuRow>,
    seen: &mut std::collections::HashMap<String, usize>,
) -> Vec<action::Action<TrayAction>> {
    rows.into_iter()
        .filter_map(|row| match row {
            MenuRow::Action {
                action,
                label,
                enabled,
            } => Some((action, label, enabled)),
            // A tab is already the nesting a submenu provided, and `window_model` never emits one.
            // Separators divide a LIST; a group of buttons is not one.
            MenuRow::Separator | MenuRow::Submenu { .. } => None,
        })
        .map(|(act, label, enabled)| {
            let occurrence = seen.entry(label.clone()).or_insert(0);
            let element = row_element_id(&label, *occurrence);
            *occurrence += 1;
            action::Action {
                weight: action::weigh(is_destructive(act)),
                element,
                label,
                enabled,
                id: act,
            }
        })
        .collect()
}

/// Whether an action destroys something the user cannot get back.
///
/// # Why one registry, here, rather than per pane
///
/// A destroy must be told apart from a save by more than the words on it, and it is the GENERIC
/// pane that renders the Account tab today — so a per-pane list meant `Remove this account from
/// this computer…` was drawn as an ordinary ghost button beside `Show my recovery phrase`. The
/// registry lives beside the one place rows become buttons, so every tab inherits it and a Phase-2
/// pane cannot forget to ask.
///
/// A closed list of ACTIONS, never a guess from the label: inferring danger from prose would make
/// the colour depend on how a menu entry happens to be phrased.
fn is_destructive(action: TrayAction) -> bool {
    matches!(
        action,
        TrayAction::RemoveAccount
            | TrayAction::ReplaceWithNewAccount
            | TrayAction::ReplaceFromPhrase
    )
}

/// Every verb on a tab, as weighted actions, in the model's order.
///
/// The whole-tab form of [`actions_in`], and the one a pane written per-tab should reach for: the
/// occurrence counter that makes each element id unique must span the TAB, and a pane that kept one
/// per section would give two identically-labelled rows the same id — which egui reports as a
/// duplicate and which leaves one of them unclickable.
pub(crate) fn actions_of(tab: &Tab) -> Vec<action::Action<TrayAction>> {
    let mut seen = std::collections::HashMap::new();
    actions_in(
        tab.sections
            .iter()
            .flat_map(|section| section.rows.iter().cloned()),
        &mut seen,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Two rows with the same label on one tab get different element ids.**
    ///
    /// The gallery disproved the label-alone version on its first screenshot: the Account tab draws
    /// `About on-chain DIDs…` twice, from two different sections, and egui painted its duplicate-id
    /// warning across the pane. The occurrence count is what separates them, and it must be counted
    /// across the whole TAB — so the fixture puts the duplicates in two sections, which is where a
    /// per-section counter gives both occurrence zero and the bug returns.
    #[test]
    fn a_label_repeated_across_two_sections_still_gets_two_ids() {
        let repeated = "About on-chain DIDs…";
        let section = |label: &str| crate::window_model::Section {
            heading: None,
            rows: vec![MenuRow::Action {
                action: TrayAction::OpenLogs,
                label: label.to_string(),
                enabled: true,
            }],
        };
        let mut seen = std::collections::HashMap::new();
        let first = actions_in(section(repeated).rows, &mut seen);
        let second = actions_in(section(repeated).rows, &mut seen);

        assert_ne!(
            first[0].element, second[0].element,
            "the same label in two sections produced one id, which egui reports as a duplicate and \
             which makes one of the two rows unclickable"
        );
        assert_eq!(first[0].element, row_element_id(repeated, 0));
        assert_eq!(second[0].element, row_element_id(repeated, 1));
    }

    /// **A destroy is drawn as a destroy on the tab that actually renders one.**
    ///
    /// The Account tab goes through the GENERIC pane, which is exactly where this was wrong: the
    /// destructive registry lived in `status.rs`, a pane with no destructive verb on it, so
    /// `Remove this account from this computer…` came out as an ordinary ghost button next to
    /// `Show my recovery phrase`. Asserted against the REAL model output rather than a fixture, so
    /// the day a destroy moves tabs this still covers it.
    #[test]
    fn the_account_tabs_destroy_is_drawn_as_destructive_and_its_siblings_are_not() {
        let view = crate::tray_menu::TrayView {
            running: true,
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            ..crate::tray_menu::TrayView::default()
        };
        let model = crate::window_model::build(&view);
        let account = model
            .tab(TabId::Account)
            .expect("an unlocked account has an Account tab");

        let mut seen = std::collections::HashMap::new();
        let rendered: Vec<action::Action<TrayAction>> = account
            .sections
            .iter()
            .flat_map(|section| actions_in(section.rows.iter().cloned(), &mut seen))
            .collect();

        let destroy = rendered
            .iter()
            .find(|a| a.id == TrayAction::RemoveAccount)
            .expect("the fixture has no destroy on it, so this proves nothing");
        assert_eq!(
            destroy.weight,
            super::super::super::render::Weight::Danger,
            "{:?} was drawn as {:?}, which is how a save looks",
            destroy.label,
            destroy.weight
        );
        assert!(
            rendered
                .iter()
                .any(|a| a.weight != super::super::super::render::Weight::Danger),
            "every verb on the tab came out destructive, so the registry is not discriminating"
        );
    }

    /// **The shared derivation promotes nothing, on any tab, in any account state.**
    ///
    /// The structural half of dig_ecosystem#2354. Every pane builds its buttons from
    /// [`actions_in`] — so once this cannot produce a `Primary`, the only way one exists anywhere in
    /// the window is a pane naming it through [`action::promote`], and "at most one primary per
    /// pane" stops being a convention anyone can forget and becomes a property of the code.
    ///
    /// Swept over every tab in every account state rather than one, because the tab set and its rows
    /// both change with the state — and the two defects the gallery caught lived in states a single
    /// fixture would not have visited: an `Unsupported` host whose only verb is a documentation
    /// link, and a Settings tab whose beacon could not be asked.
    #[test]
    fn no_tab_in_any_account_state_promotes_a_verb_by_where_it_sits() {
        use crate::tray_menu::{AccountState, TrayView};

        let mut swept = 0;
        for account in [
            AccountState::Unsupported,
            AccountState::Absent,
            AccountState::Locked,
            AccountState::Unopenable,
            AccountState::NeedsPassword,
            AccountState::Unlocked { recoverable: true },
        ] {
            let model = crate::window_model::build(&TrayView {
                running: true,
                node_connected: true,
                account: Some(account.clone()),
                cache: Some(crate::cache::CacheSnapshot {
                    cap_bytes: 10 * crate::cache::GIB,
                    used_bytes: 407 * crate::cache::MIB,
                }),
                ..TrayView::default()
            });
            for tab in &model.tabs {
                for drawn in actions_of(tab) {
                    swept += 1;
                    assert_ne!(
                        drawn.weight,
                        crate::confirm::gui::render::Weight::Primary,
                        "“{}” on the {:?} tab ({account:?}) was promoted by the derivation itself",
                        drawn.label,
                        tab.id
                    );
                }
            }
        }
        assert!(
            swept > 20,
            "only {swept} verbs were examined, which is too few to have visited the tabs this \
             guard is about"
        );
    }

    /// **…and exactly one pane still names a lead, so the window has not simply lost emphasis.**
    ///
    /// The control for the sweep above, which deleting `Weight::Primary` outright would satisfy.
    /// Account is the pane the MODEL designates a lead for — the one thing this account needs from
    /// the user right now, which `security_actions` puts at the top of its protection section in
    /// every state — and it must still be the pane's loudest control.
    #[test]
    fn the_account_pane_still_leads_with_the_verb_the_model_designates() {
        use crate::tray_menu::{AccountState, TrayView};

        let model = crate::window_model::build(&TrayView {
            running: true,
            account: Some(AccountState::Locked),
            ..TrayView::default()
        });
        let tab = model.tab(TabId::Account).expect("Account is emitted");
        let promoted = account::promoted_lead(tab).expect("a locked account leads with Unlock…");
        assert_eq!(
            promoted.id,
            TrayAction::Unlock,
            "the promoted verb is not the model's own leading protection row"
        );
        assert_eq!(
            promoted.weight,
            crate::confirm::gui::render::Weight::Primary
        );
    }

    /// The view the state sweeps are painted against.
    ///
    /// The agent is up, a node has been found and an account is open, so every tab is emitted and no
    /// sweep skips one. Every READING is left at its default absence — no cache snapshot, no node
    /// facts, no store list, no balance — which is both the real state of the window for the first
    /// seconds after it opens and the state in which an invented zero cannot be told from a reading.
    fn healthy_view() -> crate::tray_menu::TrayView {
        crate::tray_menu::TrayView {
            running: true,
            node_connected: true,
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            ..crate::tray_menu::TrayView::default()
        }
    }

    /// Every string a tab painted, with `note` forced onto it.
    fn painted_with_note(id: TabId, note: crate::window_model::PaneNote) -> Vec<String> {
        painted(healthy_view(), id, note)
    }

    /// Every string tab `id` painted from `view`, with `note` forced onto it.
    fn painted(
        view: crate::tray_menu::TrayView,
        id: TabId,
        note: crate::window_model::PaneNote,
    ) -> Vec<String> {
        let model = crate::window_model::build(&view);
        let mut tab = model
            .tab(id)
            .unwrap_or_else(|| panic!("{id:?} is not emitted by the fixture"))
            .clone();
        tab.note = note;
        let facts = PaneFacts::of_tray(&view);

        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let t = crate::confirm::gui::theme::Theme::Light.tokens();
        let screen = Rect::from_min_size(egui::Pos2::ZERO, egui::Vec2::new(960.0, 4_000.0));

        let mut output = egui::FullOutput::default();
        // Two frames: the first builds the font atlas, the second lays out against it.
        for _ in 0..2 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("pane-state-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            let column = Rect::from_min_size(
                                screen.left_top(),
                                egui::Vec2::new(screen.width() - space::S5 * 2.0, f32::INFINITY),
                            );
                            draw_tab(ui, column, &t, &tab, &facts, Default::default(), true);
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
        said
    }

    /// **Every pane presents every state, in the same words, drawn by the frame (dig_ecosystem#2356).**
    ///
    /// The property: one cause produces one presentation, whichever tab a person is looking at. When
    /// the node is unreachable, all five tabs must say the unreachable thing the same way — the
    /// failure this guards against is four presentations of one cause on one screen.
    ///
    /// The sweep is every tab × every note, and the assertion is on the note's own SENTENCE reaching
    /// the screen verbatim. That is what catches the drift the ticket describes: a pane that took
    /// over its own banner, softened the wording, or swallowed a state it did not expect would fail
    /// here for that tab alone, while the other six stayed green — which is precisely how the panes
    /// came to disagree in the first place.
    ///
    /// `Ready` is asserted from the other side, because it is the one state that draws NOTHING: a
    /// pane that painted a "loaded successfully" banner would satisfy any it-says-something check.
    #[test]
    fn every_tab_presents_every_state_in_the_same_words() {
        use crate::window_model::PaneNote;

        let sentences = [
            ("waiting", "The DIG agent is still starting."),
            (
                "unreachable",
                "No node is connected, so nothing here is live.",
            ),
            ("empty", "There is nothing on this tab yet."),
        ];
        let notes = |which: usize, text: &'static str| match which {
            0 => PaneNote::Waiting(text),
            1 => PaneNote::Unreachable(text),
            _ => PaneNote::Empty(text),
        };

        for tab in TabId::all() {
            for (which, (name, sentence)) in sentences.iter().enumerate() {
                let said = painted_with_note(tab, notes(which, sentence));
                assert!(
                    said.iter().any(|line| line == sentence),
                    "the {tab:?} pane did not present its {name} state in the model's own words. \
                     One cause must read the same on every tab; it painted: {said:?}"
                );
            }

            let ready = painted_with_note(tab, PaneNote::Ready);
            for (_, sentence) in sentences {
                assert!(
                    !ready.iter().any(|line| line == sentence),
                    "the {tab:?} pane painted a state banner while ready — success shows itself, \
                     and a banner over a working pane teaches people to skip banners"
                );
            }
        }
    }

    /// **On a computer where nothing has been read, no tab paints a zero** (dig_ecosystem#2397).
    ///
    /// # What this replaces, and why it is the better guard
    ///
    /// It stands where `every_unwired_surface_says_so_in_the_same_words` did. That sweep checked
    /// that the two skeleton cards carried the *"Not wired up"* badge and its caveat identically,
    /// and it carried a vacuity guard insisting at least two panes still drew them — written to fail
    /// "the day the last skeleton is plumbed in". This is that day: both cards read the node now, so
    /// the fifth state and its words are gone.
    ///
    /// The property they were protecting is not. A card wired to a node is one refresh away from
    /// having no answer, and the failure is the same one: a figure the reader cannot tell from a
    /// reading. So the sweep runs against the state where every reading is genuinely absent and
    /// asserts that nothing on any tab comes out as a quantity.
    ///
    /// That state is `healthy_view` rather than [`TrayView::default`](crate::tray_menu::TrayView::default),
    /// and the difference is what makes the sweep bite. `healthy_view` sets only `running`,
    /// `node_connected` and an unlocked account — every READING (`cache`, `node_facts`,
    /// `hosted_stores`, `balance`) is left at its default absence. So the panes draw their full
    /// layout, with nothing to put in it. A bare `TrayView::default` would instead render the
    /// no-account state on most tabs, and the sweep would pass by having almost no text to examine
    /// — which is the failure the `said.len() > 3` control below exists to catch.
    ///
    /// It is asserted over the painted TEXT rather than over the values, because the values are
    /// where the honesty types already hold: `Value::Unknown` and the three-state readings make a
    /// zero hard to construct, and this catches the ways round them — a `Value::Word("0")`, a
    /// formatted `0 B`, an `up 0 minutes`. The control below keeps it from passing on a window that
    /// simply painted nothing.
    #[test]
    fn no_tab_paints_a_zero_when_nothing_has_been_read() {
        use crate::window_model::PaneNote;

        // The shapes a not-yet-known figure takes when it is drawn as one anyway. Substrings rather
        // than whole lines, because each of these is how the app's own formatters render a zero.
        let inventions = ["0 B", "0 stores", "0 capsules", "up 0", "0 of "];

        for tab in TabId::all() {
            let said = painted_with_note(tab, PaneNote::Ready);
            for line in &said {
                for invented in inventions {
                    assert!(
                        !line.contains(invented),
                        "the {tab:?} pane painted {line:?} on a computer that has reported \
                         nothing. A zero a reader cannot tell from a reading is the one thing this \
                         window may not draw"
                    );
                }
                assert_ne!(
                    line.trim(),
                    "0",
                    "the {tab:?} pane painted a bare zero where a figure goes"
                );
            }
            assert!(
                said.len() > 3,
                "the {tab:?} pane painted almost nothing ({said:?}), so this sweep is passing \
                 because there was no text to examine"
            );
        }
    }

    /// An id is derived from the label and occurrence only — never from a position on screen.
    #[test]
    fn a_row_id_does_not_depend_on_where_the_row_was_drawn() {
        assert_eq!(row_element_id("Unlock…", 0), row_element_id("Unlock…", 0));
        assert_ne!(row_element_id("Unlock…", 0), row_element_id("Unlock…", 1));
        assert_ne!(row_element_id("Unlock…", 0), row_element_id("Lock now", 0));
    }
}
