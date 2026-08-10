//! The Settings tab: one card per group of settings, in the order a person needs them.
//!
//! # What each group is, and who decides it
//!
//! **Updates** is [`crate::tray_menu`]'s, entirely. PR #120 decided which update verbs exist, what
//! each costs, and what the beacon's state means; this card re-presents that decision with room for
//! the sentence and the figures a menu row has no space for. It does not re-decide any of it — and,
//! critically, it reads the BEACON for what is true, never [`AgentConfig::auto_update`], which is
//! only what somebody once asked for. Those are different facts (see [`crate::auto_update`]), and
//! showing the wish as though it were the state is how a machine that had opted out came to be told
//! it was up to date.
//!
//! **Connection** and **Shortcut** are fields of `agent.json` that no menu has ever offered
//! (dig_ecosystem#2331). §5.3 requires a user-facing custom-node setting on every DIG client, and
//! dig-app's was reachable only by hand-editing a JSON file. They are forms, not verbs, so they are
//! written here rather than dispatched — see [`prefs`] for that boundary and for the read-back that
//! keeps a failed write from being drawn as a success.
//!
//! # This pane has no primary control, deliberately (dig_ecosystem#2354)
//!
//! A settings page is a set of independent groups, and there is no one act a person came here to
//! perform — so every control on it is drawn as a peer. When emphasis was assigned by position, this
//! tab's loudest, brightest control was *"Turn auto-update off (asks for administrator)…"*: the most
//! prominent thing on the screen disabled a safety feature, and nobody chose that. It was simply
//! where the row happened to sit. A pane with no primary is a correct outcome, and this is one.
//!
//! # Every group states its cost above its controls
//!
//! PR #120's rule, generalised: a control whose real price is only revealed after it is clicked is a
//! surprise, and a person who would have declined has already been interrupted. So the elevation,
//! the restart and the chord Windows gives up are all said in the card, before the button.

pub(crate) mod prefs;
pub(crate) mod probe;

use egui::Ui;

use super::action::{self, Action};
use super::card;
use super::copy;
use super::data::{self, Readout, Tone, Value};
use super::facts::PaneFacts;
use super::field::{self, Field};
use super::flow::Flow;
use super::select::{self, Choice};
use super::state::{self, PaneState};
use super::text;
use crate::auto_update::{BeaconStatus, UpdateChannel};
use crate::config::AgentConfig;
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::tray_menu::TrayAction;
use crate::window_model::Tab;
use prefs::{ConfigStore, Setting};
use probe::Probe;

/// A control on this pane that is NOT one of the model's verbs.
///
/// Deliberately a separate type from [`TrayAction`]: these do not go to the worker and the shell
/// never sees them, so a form control cannot be mistaken for a decided verb — nor accidentally
/// dispatched as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Local {
    /// Write the typed node address.
    SaveNode,
    /// Clear the node address, back to the automatic ladder.
    AutomaticNode,
    /// Dial the address and report what answers.
    TestNode,
    /// Write the typed shortcut.
    SaveShortcut,
    /// Clear the shortcut, back to the shipped chord.
    DefaultShortcut,
    /// Turn the funds-arrived notification on or off (dig_ecosystem#2548).
    SetNotifications(bool),
}

/// Draw the Settings pane's content into `flow`, and report the MODEL action pressed.
///
/// The form controls are handled inside this module — they write a file, they do not dispatch a
/// verb — so the only thing that leaves here is one of the model's own actions.
pub(crate) fn draw(
    flow: &mut Flow,
    t: &Tokens,
    tab: &Tab,
    facts: &PaneFacts,
) -> Option<TrayAction> {
    let pressed = updates_card(flow, t, tab, facts);
    flow.gap(space::S4);

    // Loaded through a zero-height block because the cards below need it before they lay out, and a
    // pane has no other way to reach the frame's `Ui`.
    let mut session = flow.place(|ui, _| (0.0, Session::load(ui)));
    connection_card(flow, t, &mut session);
    flow.gap(space::S4);
    shortcut_card(flow, t, &mut session);
    flow.gap(space::S4);
    notifications_card(flow, t, &mut session);
    flow.place(|ui, _| (0.0, session.store(ui)));

    pressed
}

// ---------------------------------------------------------------------------------------------
// Updates — PR #120's group, re-presented
// ---------------------------------------------------------------------------------------------

/// What the update rows the model offered are, by what they do.
struct UpdateRows {
    /// Turning updates on or off, or re-arming the schedule: whichever ONE the model chose.
    toggle: Vec<Action<TrayAction>>,
    /// The channel choice, in the model's order.
    channels: Vec<Action<TrayAction>>,
    /// The explainer, and anything else the model puts here later.
    other: Vec<Action<TrayAction>>,
}

/// Sort a tab's verbs into the three groups this card lays out.
///
/// A match on the ACTION, never on the label: the labels are sentences that change with the beacon's
/// state, and grouping by their words would re-sort itself the first time one was reworded.
fn sort_rows(tab: &Tab) -> UpdateRows {
    let mut rows = UpdateRows {
        toggle: Vec::new(),
        channels: Vec::new(),
        other: Vec::new(),
    };
    for action in super::actions_of(tab) {
        match action.id {
            TrayAction::SetAutoUpdate { .. } | TrayAction::RearmUpdateSchedule => {
                rows.toggle.push(action)
            }
            TrayAction::SetUpdateChannel(_) => rows.channels.push(action),
            _ => rows.other.push(action),
        }
    }
    rows
}

/// The updates group: what is true now, what changing it costs, and the model's verbs.
///
/// # Why the model's own group heading is not drawn here
///
/// `window_model` gives this section a heading — `Auto-update — on, following the Stable channel` —
/// which is exactly what a tray submenu's parent row needs, because a menu has nowhere else to put
/// the fact. A card does: the badge says on-or-off at a glance and the readouts say which channel
/// and what the schedule is, from the SAME `BeaconStatus` the heading is computed from. Drawing all
/// three said one fact three times, and the card read as though it were insisting.
fn updates_card(flow: &mut Flow, t: &Tokens, tab: &Tab, facts: &PaneFacts) -> Option<TrayAction> {
    let rows = sort_rows(tab);
    let status = facts.update;
    let live = flow.live();

    flow.place(|ui, at| {
        let (height, pressed) = card::interactive_card(
            ui,
            at,
            t,
            live,
            Some(copy::settings::UPDATES_CARD),
            |inner| {
                inner.place(|ui, at| (text::caption(ui, at, t, copy::settings::UPDATES_ABOUT), ()));
                inner.gap(space::S3);
                if let Some(status) = status {
                    let (word, tone) = beacon_word(status);
                    inner.place(|ui, at| {
                        (data::badge(ui, at.left_top(), t, word, tone).height(), ())
                    });
                    inner.gap(space::S3);
                    // Stacked, one per row, rather than through `data::readouts` — which lays two
                    // columns out side by side where there is width for it. That is right for the
                    // four short facts on Status; here it put `Stable` immediately beside
                    // `Daily check`, and the two ran together as one sentence when read.
                    for item in beacon_readouts(status) {
                        inner.place(|ui, at| (data::readout(ui, at, t, &item), ()));
                        inner.gap(space::S3);
                    }
                    inner.gap(space::S2);
                }

                let mut hit = None;
                if !rows.toggle.is_empty() || !rows.channels.is_empty() {
                    inner.place(|ui, at| {
                        (text::caption(ui, at, t, copy::settings::UPDATES_COST), ())
                    });
                    inner.gap(space::S3);
                }
                if !rows.toggle.is_empty() {
                    hit = hit
                        .or(inner.place(|ui, at| action::buttons(ui, at, t, live, &rows.toggle)));
                    inner.gap(space::S4);
                }
                if !rows.channels.is_empty() {
                    hit = hit.or(channel_panel(inner, t, live, &rows.channels, status));
                    inner.gap(space::S4);
                }
                hit.or(inner.place(|ui, at| action::buttons(ui, at, t, live, &rows.other)))
            },
        );
        (height, pressed.flatten())
    })
}

/// The channel choice, as a dropdown, with the caution for each switch stated BEFORE the control.
///
/// # Why a dropdown rather than a row of buttons
///
/// It is a SETTING with one value in force, not a pair of things to do, and a chooser is what says
/// that. (User directive, 2026-08-08.) The options are still the model's rows, verbatim — including
/// the word marking the one in force, which `tray_menu::channel_row_label` writes as a WORD because
/// this window's font stack has no U+2713 and a tick photographs as a tofu box.
///
/// # Why the caution is here and not only at the prompt
///
/// It is [`crate::auto_update::switch_caution`]'s own sentence — the same one the confirm prompt
/// shows — and both directions are stated. A person learns that following stable again can move this
/// computer back to an older build while they are DECIDING, not while they are being asked to agree
/// to it. The prompt still asks; this only means the answer is not a surprise.
fn channel_panel(
    flow: &mut Flow,
    t: &Tokens,
    live: bool,
    channels: &[Action<TrayAction>],
    status: Option<BeaconStatus>,
) -> Option<TrayAction> {
    let cautions: Vec<&'static str> = match status {
        None => Vec::new(),
        Some(status) => UpdateChannel::ALL
            .iter()
            .filter_map(|to| crate::auto_update::switch_caution(status.channel, *to))
            .collect(),
    };
    let options: Vec<Choice<TrayAction>> = channels
        .iter()
        .map(|action| Choice {
            label: action.label.clone(),
            id: action.id,
        })
        .collect();
    let selected = status.and_then(|status| channel_in_force(channels, status.channel));

    flow.place(|ui, at| {
        let mut hit = None;
        let height = card::panel(ui, at, t, Some(copy::settings::CHANNEL_PANEL), |inner| {
            for caution in &cautions {
                inner.place(|ui, at| (text::caption(ui, at, t, caution), ()));
                inner.gap(space::S3);
            }
            hit = inner.place(|ui, at| {
                select::select(
                    ui,
                    at,
                    t,
                    live,
                    &select::Select {
                        label: copy::settings::CHANNEL_FIELD,
                        options: &options,
                        selected,
                        unknown: copy::settings::CHANNEL_UNKNOWN,
                        id: egui::Id::new("dig-settings-channel"),
                    },
                )
            });
        });
        (height, hit)
    })
}

/// Which of the model's channel rows is the one the beacon reports.
///
/// Matched on the CHANNEL the row's action carries, never on its label: the labels are sentences
/// that change with the state, and a chooser that found its selection by looking for the word
/// "current" in them would silently show nothing the first time that wording changed.
fn channel_in_force(channels: &[Action<TrayAction>], current: UpdateChannel) -> Option<usize> {
    channels
        .iter()
        .position(|action| matches!(action.id, TrayAction::SetUpdateChannel(c) if c == current))
}

/// The beacon's state as one word and how worried to be about it.
///
/// [`BeaconStatus::updates_are_live`] rather than `paused`, because either fact alone stops updates
/// happening and reading only the pause flag is what told an opted-out machine it was up to date.
///
/// `Warn` and not a stronger tone: updates being off is a state to act on, not a fault, and the
/// model draws no alarming banner beside it — two things on one screen describing one fact must not
/// disagree about how bad it is (the badge-versus-banner contradiction #124 removed).
fn beacon_word(status: BeaconStatus) -> (&'static str, Tone) {
    match status.updates_are_live() {
        true => ("Updates on", Tone::Good),
        false => ("Updates off", Tone::Warn),
    }
}

/// The two figures the beacon reports, as readouts.
fn beacon_readouts(status: BeaconStatus) -> Vec<Readout> {
    vec![
        Readout::new(
            copy::settings::CHANNEL_LABEL,
            Value::Word(status.channel.display_name().to_string()),
        ),
        Readout::new(
            copy::settings::SCHEDULE_LABEL,
            Value::Word(schedule_word(status).to_string()),
        ),
    ]
}

/// Whether the daily check exists on this machine, in words.
///
/// A separate readout from the badge because it is a separate fact: a paused beacon still wakes, and
/// an opted-out one never does. Collapsing them would hide the one a `resume` cannot fix.
fn schedule_word(status: BeaconStatus) -> &'static str {
    match (status.schedule_opted_out, status.paused) {
        (true, _) => "Removed from this computer",
        (false, true) => "Scheduled, but paused",
        (false, false) => "Scheduled daily",
    }
}

// ---------------------------------------------------------------------------------------------
// The two settings this pane writes
// ---------------------------------------------------------------------------------------------

/// The node this computer reads through.
fn connection_card(flow: &mut Flow, t: &Tokens, session: &mut Session) {
    let live = flow.live();
    setting_card(
        flow,
        t,
        session,
        Setting::NodeUrl,
        copy::settings::NODE_CARD,
        copy::settings::NODE_ABOUT,
        copy::settings::NODE_EFFECTIVE,
        copy::settings::NODE_COST,
        Field {
            label: copy::settings::NODE_FIELD,
            placeholder: copy::settings::NODE_PLACEHOLDER,
            help: copy::settings::NODE_HELP,
            error: None,
            id: egui::Id::new("dig-settings-node-url"),
        },
        &[
            (Local::SaveNode, copy::settings::NODE_SAVE),
            (Local::TestNode, copy::settings::NODE_TEST),
            (Local::AutomaticNode, copy::settings::NODE_AUTOMATIC),
        ],
        live,
        true,
    );
}

/// The chord that opens the address bar.
fn shortcut_card(flow: &mut Flow, t: &Tokens, session: &mut Session) {
    let live = flow.live();
    setting_card(
        flow,
        t,
        session,
        Setting::Shortcut,
        copy::settings::SHORTCUT_CARD,
        copy::settings::SHORTCUT_ABOUT,
        copy::settings::SHORTCUT_EFFECTIVE,
        copy::settings::SHORTCUT_COST,
        Field {
            label: copy::settings::SHORTCUT_FIELD,
            placeholder: crate::hotkey::DEFAULT_SHORTCUT,
            help: copy::settings::SHORTCUT_HELP,
            error: None,
            id: egui::Id::new("dig-settings-shortcut"),
        },
        &[
            (Local::SaveShortcut, copy::settings::SHORTCUT_SAVE),
            (Local::DefaultShortcut, copy::settings::SHORTCUT_DEFAULT),
        ],
        live,
        false,
    );
}

/// Whether DIG says anything when money arrives (dig_ecosystem#2548).
///
/// # Why a chooser rather than a button
///
/// It is a setting with one value in force, which is what [`select`] is for — the same reasoning
/// that made the update channel a dropdown (user directive, 2026-08-08). A pair of buttons would
/// read as two things to DO, and the design system has no checkbox to reach for instead.
///
/// # Why the limitation is in the card
///
/// A notification a person is told to expect and does not get is worse than one they were never
/// promised. DIG only notices a payment while it is running, so the card says so before the control
/// rather than leaving it to be discovered — the same rule the other two groups follow with their
/// costs.
fn notifications_card(flow: &mut Flow, t: &Tokens, session: &mut Session) {
    let live = flow.live();
    let unreadable = session.unreadable.clone();
    let enabled = session.config.notifications.funds_received;
    let options = [
        Choice {
            label: copy::settings::NOTIFY_ON.to_string(),
            id: Local::SetNotifications(true),
        },
        Choice {
            label: copy::settings::NOTIFY_OFF.to_string(),
            id: Local::SetNotifications(false),
        },
    ];
    let selected = Some(usize::from(!enabled));
    let note = session.notifications.saved.then_some(copy::settings::SAVED);

    let hit = flow.place(|ui, at| {
        let mut hit = None;
        let height = card::interactive_card(
            ui,
            at,
            t,
            live,
            Some(copy::settings::NOTIFY_CARD),
            |inner| {
                inner.place(|ui, at| (text::caption(ui, at, t, copy::settings::NOTIFY_ABOUT), ()));
                inner.gap(space::S3);

                if let Some(why) = &unreadable {
                    inner.place(|ui, at| {
                        (
                            state::banner(ui, at, t, &PaneState::Unreachable(why.clone())),
                            (),
                        )
                    });
                    return;
                }

                inner.place(|ui, at| {
                    (
                        data::readout(
                            ui,
                            at,
                            t,
                            &Readout::new(
                                copy::settings::NOTIFY_EFFECTIVE,
                                Value::Word(effective_notification(enabled).to_string()),
                            ),
                        ),
                        (),
                    )
                });
                inner.gap(space::S4);
                inner.place(|ui, at| (text::caption(ui, at, t, copy::settings::NOTIFY_COST), ()));
                inner.gap(space::S3);
                hit = inner.place(|ui, at| {
                    select::select(
                        ui,
                        at,
                        t,
                        live,
                        &select::Select {
                            label: copy::settings::NOTIFY_FIELD,
                            options: &options,
                            selected,
                            unknown: copy::settings::NOTIFY_OFF,
                            id: egui::Id::new("dig-settings-notifications"),
                        },
                    )
                });
                if let Some(note) = note {
                    inner.gap(space::S3);
                    inner.place(|ui, at| (text::caption(ui, at, t, note), ()));
                }
            },
        )
        .0;
        (height, hit)
    });
    if let Some(Local::SetNotifications(wanted)) = hit {
        session.act_locally(Local::SetNotifications(wanted));
    }
}

/// What DIG will do when money arrives, in the words of the thing that will happen.
///
/// Derived from the stored value rather than from the chooser's own selection, so a save that did
/// not land shows what the file says (the [`prefs`] read-back rule) instead of what was clicked.
fn effective_notification(enabled: bool) -> &'static str {
    match enabled {
        true => copy::settings::NOTIFY_ON,
        false => copy::settings::NOTIFY_OFF,
    }
}

/// One settings group: what it is, what it costs, the field, its controls, and what happened.
///
/// Both groups are the same shape — a value with a validator, an escape back to the default, and a
/// read-back after every write — so they are one function taking the parts that differ. A second
/// copy of this layout would be the drift this whole design system exists to end.
#[allow(clippy::too_many_arguments)]
fn setting_card(
    flow: &mut Flow,
    t: &Tokens,
    session: &mut Session,
    setting: Setting,
    title: &str,
    about: &str,
    effective_label: &str,
    cost: &str,
    field: Field<'_>,
    controls: &[(Local, &str)],
    live: bool,
    testable: bool,
) {
    let unreadable = session.unreadable.clone();
    flow.place(|ui, at| {
        let (height, hit) = card::interactive_card(ui, at, t, live, Some(title), |inner| {
            inner.place(|ui, at| (text::caption(ui, at, t, about), ()));
            inner.gap(space::S3);

            // A settings file that cannot be read gets an explanation INSTEAD of the controls. A
            // disabled form is a form somebody will fight with; PR #120 established the same rule
            // for a beacon that will not answer.
            if let Some(why) = &unreadable {
                inner.place(|ui, at| {
                    (
                        state::banner(ui, at, t, &PaneState::Unreachable(why.clone())),
                        (),
                    )
                });
                return None;
            }

            inner.place(|ui, at| {
                (
                    data::readout(
                        ui,
                        at,
                        t,
                        &Readout::new(
                            effective_label,
                            Value::Identifier(setting.effective(&session.config)),
                        ),
                    ),
                    (),
                )
            });
            inner.gap(space::S4);
            inner.place(|ui, at| (text::caption(ui, at, t, cost), ()));
            inner.gap(space::S3);

            let field = Field {
                error: session.error(setting).cloned(),
                ..field
            };
            let before = session.draft(setting).clone();
            inner.place(|ui, at| {
                (
                    field::text_field(ui, at, t, live, &field, session.draft_mut(setting)),
                    (),
                )
            });
            if *session.draft(setting) != before {
                // An answer about the address that WAS typed is worse than no answer at all.
                session.edited(setting);
            }
            inner.gap(space::S3);

            let actions: Vec<Action<Local>> = controls
                .iter()
                .map(|(id, label)| Action {
                    label: (*label).to_string(),
                    weight: Weight::Ghost,
                    enabled: true,
                    id: *id,
                    element: egui::Id::new(("dig-settings-control", *label)),
                })
                .collect();
            let hit = inner.place(|ui, at| action::buttons(ui, at, t, live, &actions));

            if let Some(note) = session.note(setting) {
                inner.gap(space::S3);
                inner.place(|ui, at| (text::caption(ui, at, t, &note), ()));
            }
            if testable {
                if let Some((word, tone, sentence)) = session.probe_report() {
                    inner.gap(space::S3);
                    inner.place(|ui, at| {
                        (data::badge(ui, at.left_top(), t, word, tone).height(), ())
                    });
                    if let Some(sentence) = sentence {
                        inner.gap(space::S2);
                        inner.place(|ui, at| (text::caption(ui, at, t, &sentence), ()));
                    }
                }
            }
            hit
        });
        // Acted on OUT here, where the frame's `Ui` is in scope: starting a connection test needs
        // the context to repaint when its answer lands, and a `Flow` deliberately hands out a `Ui`
        // only for the width of one block.
        if let Some(control) = hit.flatten() {
            session.act(ui, control);
        }
        (height, ())
    });
}

// ---------------------------------------------------------------------------------------------
// The pane's own state, across frames
// ---------------------------------------------------------------------------------------------

/// What the person has typed, what the file says, and what the last test found.
///
/// Held in the frame context rather than in the shell, because the shell knows nothing about these
/// settings and a form's half-typed value is not application state (`window_model.rs` and
/// `shell.rs` are where a second implementation of the rules would take root, and this is not one).
#[derive(Clone)]
struct Session {
    /// The config as the file last reported it — the source for every value shown.
    config: AgentConfig,
    /// Why the settings file cannot be read, when it cannot.
    unreadable: Option<String>,
    /// Where the settings are read from and written to. `None` on a host with nowhere to keep them.
    ///
    /// Held rather than resolved per press so a save can be exercised against a store in memory —
    /// including one that loses its writes, which is the case the read-back exists for.
    store: Option<std::sync::Arc<dyn ConfigStore>>,
    node: FieldState,
    shortcut: FieldState,
    /// The notification switch's own "Saved." state. It has no typed value and no error — a choice
    /// cannot be malformed — so only the confirmation half of [`FieldState`] is used.
    notifications: FieldState,
    tester: probe::Tester,
}

/// One field's typed value and what last happened to it.
#[derive(Clone, Default)]
struct FieldState {
    typed: String,
    error: Option<String>,
    saved: bool,
}

/// The id the session is kept under, for the life of the window.
fn session_id() -> egui::Id {
    egui::Id::new("dig-settings-session")
}

impl Session {
    /// This window's session, reading the settings file the first time it is asked for.
    fn load(ui: &Ui) -> Self {
        if let Some(held) = ui.data(|d| d.get_temp::<Self>(session_id())) {
            return held;
        }
        let store = prefs::FileStore::for_host()
            .map(|store| std::sync::Arc::new(store) as std::sync::Arc<dyn ConfigStore>);
        let fresh = Self::from_store(store);
        ui.data_mut(|d| d.insert_temp(session_id(), fresh.clone()));
        fresh
    }

    /// A session over `store`, or over nothing when this host has no settings file at all.
    fn from_store(store: Option<std::sync::Arc<dyn ConfigStore>>) -> Self {
        let read = match &store {
            None => Err(copy::settings::NO_CONFIG.to_string()),
            Some(store) => store.read(),
        };
        let (config, unreadable) = match read {
            Ok(config) => (config, None),
            Err(why) => (AgentConfig::default(), Some(why)),
        };
        Self {
            node: FieldState {
                typed: Setting::NodeUrl.stored(&config),
                ..FieldState::default()
            },
            shortcut: FieldState {
                typed: Setting::Shortcut.stored(&config),
                ..FieldState::default()
            },
            config,
            unreadable,
            store,
            notifications: FieldState::default(),
            tester: probe::Tester::default(),
        }
    }

    fn store(&self, ui: &Ui) {
        ui.data_mut(|d| d.insert_temp(session_id(), self.clone()));
    }

    fn field(&self, setting: Setting) -> &FieldState {
        match setting {
            Setting::NodeUrl => &self.node,
            Setting::Shortcut => &self.shortcut,
        }
    }

    fn field_mut(&mut self, setting: Setting) -> &mut FieldState {
        match setting {
            Setting::NodeUrl => &mut self.node,
            Setting::Shortcut => &mut self.shortcut,
        }
    }

    fn draft(&self, setting: Setting) -> &String {
        &self.field(setting).typed
    }

    fn draft_mut(&mut self, setting: Setting) -> &mut String {
        &mut self.field_mut(setting).typed
    }

    fn error(&self, setting: Setting) -> Option<&String> {
        self.field(setting).error.as_ref()
    }

    /// The line under a field's controls: the confirmation of a save, or nothing.
    ///
    /// Never a confirmation and an error at once — the error lives on the field that caused it, and
    /// a card saying "Saved." above a red field would be two answers to one question.
    fn note(&self, setting: Setting) -> Option<String> {
        self.field(setting)
            .saved
            .then(|| copy::settings::SAVED.to_string())
    }

    /// Typing clears the last answer about this field: the confirmation, the error, and — for the
    /// node — a connection test that was about a different address.
    fn edited(&mut self, setting: Setting) {
        let field = self.field_mut(setting);
        field.saved = false;
        field.error = None;
        if setting == Setting::NodeUrl {
            self.tester.forget();
        }
    }

    /// Run one of this pane's own controls.
    ///
    /// The connection test is the only one that needs the frame at all — it has to ask the context
    /// to repaint when its answer arrives — so everything else goes through [`act_locally`], which a
    /// test can drive without a window.
    fn act(&mut self, ui: &Ui, control: Local) {
        match control {
            Local::TestNode => {
                // The address that is SAVED, not the one being typed: a test against half a
                // hostname would answer a question nobody asked.
                let configured = self.config.node_url.clone();
                self.tester.start(ui.ctx(), configured);
            }
            settled => self.act_locally(settled),
        }
    }

    /// The controls that only touch the settings file.
    fn act_locally(&mut self, control: Local) {
        match control {
            Local::SaveNode => self.save(Setting::NodeUrl, None),
            Local::AutomaticNode => self.save(Setting::NodeUrl, Some(String::new())),
            Local::SaveShortcut => self.save(Setting::Shortcut, None),
            Local::DefaultShortcut => self.save(Setting::Shortcut, Some(String::new())),
            Local::SetNotifications(wanted) => self.save_notifications(wanted),
            // Handled by [`act`], which holds the context it needs. An arm rather than a catch-all
            // so a control added later cannot quietly fall through to doing nothing.
            Local::TestNode => {}
        }
    }

    /// Turn notifications on or off, and adopt whatever the file says afterwards.
    ///
    /// The adopted config is the one [`prefs::save_notifications`] read BACK, so a write that
    /// silently did not land leaves the chooser showing what is stored — never what was clicked.
    fn save_notifications(&mut self, wanted: bool) {
        let Some(store) = self.store.clone() else {
            self.unreadable = Some(copy::settings::NO_CONFIG.to_string());
            return;
        };
        match prefs::save_notifications(store.as_ref(), wanted) {
            Ok(config) => {
                self.config = config;
                self.notifications.saved = true;
            }
            Err(problem) => {
                self.unreadable = Some(problem);
                self.notifications.saved = false;
            }
        }
    }

    /// Write a setting and adopt whatever the file says afterwards.
    ///
    /// `override_with` is how the escape hatches work: they save an EMPTY value, which clears the
    /// setting, and the field then shows what is stored rather than what was in it — so a person who
    /// typed a bad address is one press from a working one.
    ///
    /// The config adopted is the one [`prefs::save`] read BACK. That is the honesty rule: a write
    /// that silently did not land leaves this pane showing the old value, never the typed one.
    fn save(&mut self, setting: Setting, override_with: Option<String>) {
        let Some(store) = self.store.clone() else {
            self.unreadable = Some(copy::settings::NO_CONFIG.to_string());
            return;
        };
        if let Some(text) = &override_with {
            self.field_mut(setting).typed = text.clone();
        }
        let typed = self.draft(setting).clone();
        match prefs::save(store.as_ref(), setting, &typed) {
            Ok(config) => {
                self.field_mut(setting).typed = setting.stored(&config);
                self.field_mut(setting).error = None;
                self.field_mut(setting).saved = true;
                self.config = config;
                if setting == Setting::NodeUrl {
                    self.tester.forget();
                }
            }
            Err(problem) => {
                self.field_mut(setting).error = Some(problem);
                self.field_mut(setting).saved = false;
            }
        }
    }

    /// What the last connection test is saying, if anything: a badge word, its tone, and the detail.
    fn probe_report(&self) -> Option<(&'static str, Tone, Option<String>)> {
        match self.tester.state() {
            Probe::Idle => None,
            Probe::Asking => Some((copy::settings::TESTING, Tone::Neutral, None)),
            Probe::Answered(Ok(endpoint)) => Some((
                "Answered",
                Tone::Good,
                Some(format!("{endpoint} answered, so DIG can read through it.")),
            )),
            Probe::Answered(Err(why)) => Some(("No answer", Tone::Warn, Some(why))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto_update::UpdateChannel;
    use crate::tray_menu::TrayView;
    use prefs::tests::FakeStore;

    /// A beacon status with everything spelled out, so a fixture cannot mean two things.
    fn beacon(paused: bool, opted_out: bool, channel: UpdateChannel) -> BeaconStatus {
        BeaconStatus {
            paused,
            schedule_opted_out: opted_out,
            channel,
        }
    }

    /// **An opted-out machine reads as OFF even though it is not paused.**
    ///
    /// The pair is the whole point: `paused` alone is false in both rows below, so a badge derived
    /// from it would call the second machine up to date. That is the defect PR #120's gate found,
    /// and this is the pane-level guard against re-introducing it in a badge.
    #[test]
    fn a_machine_that_never_wakes_is_not_reported_as_up_to_date() {
        let live = beacon(false, false, UpdateChannel::Stable);
        let never_wakes = beacon(false, true, UpdateChannel::Stable);
        assert_eq!(beacon_word(live).0, "Updates on");
        assert_eq!(
            beacon_word(never_wakes).0,
            "Updates off",
            "a beacon whose schedule was removed was drawn as though updates were running"
        );
        assert_ne!(beacon_word(live).1, beacon_word(never_wakes).1);
    }

    /// **The three ways the daily check can stand are told apart.**
    ///
    /// A removed schedule and a pause need different remedies — one is re-armed, the other resumed —
    /// so a readout that said "not running" for both would send half its readers to the wrong verb.
    #[test]
    fn the_schedule_readout_separates_a_pause_from_a_removal() {
        let words = [
            schedule_word(beacon(false, false, UpdateChannel::Stable)),
            schedule_word(beacon(true, false, UpdateChannel::Stable)),
            schedule_word(beacon(false, true, UpdateChannel::Stable)),
        ];
        let mut unique = words.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            3,
            "two schedule states share a sentence: {words:?}"
        );
    }

    /// **The card shows the beacon's channel, not the one remembered in `agent.json`.**
    ///
    /// The two disagree exactly when a change was asked for and did not take, which is the moment
    /// this surface must not lie. The readouts are built from the beacon alone — the config is not
    /// even a parameter — and the fixture makes them disagree so a wiring that preferred the config
    /// would fail here.
    #[test]
    fn the_channel_shown_is_the_beacons_and_not_the_remembered_wish() {
        let wished = AgentConfig {
            auto_update: crate::auto_update::AutoUpdate {
                enabled: true,
                channel: UpdateChannel::Nightly,
            },
            ..AgentConfig::default()
        };
        let readouts = beacon_readouts(beacon(false, true, UpdateChannel::Stable));
        let following = readouts
            .iter()
            .find(|r| r.label == copy::settings::CHANNEL_LABEL)
            .expect("the card names the channel");
        assert_eq!(
            following.value,
            Value::Word(UpdateChannel::Stable.display_name().to_string()),
            "the card showed the remembered channel ({:?}) rather than the beacon's",
            wished.auto_update.channel
        );
        assert!(
            beacon_word(beacon(false, true, UpdateChannel::Stable))
                .0
                .contains("off"),
            "the card said updates were on for a machine whose schedule is gone, while \
             agent.json's remembered preference said enabled"
        );
    }

    /// **Every update verb the model offers is rendered, in exactly one group.**
    ///
    /// The sort is by action, and a verb that matched no arm would silently vanish — which on this
    /// tab means the only way to turn updates back on disappears. Asserted against the REAL model in
    /// the state that offers the most rows.
    #[test]
    fn no_update_verb_is_dropped_by_the_grouping() {
        let view = TrayView {
            running: true,
            update: Some(beacon(true, false, UpdateChannel::Stable)),
            ..TrayView::default()
        };
        let model = crate::window_model::build(&view);
        let tab = model
            .tab(crate::window_model::TabId::Settings)
            .expect("Settings renders in every state");

        let rows = sort_rows(tab);
        let rendered: Vec<TrayAction> = rows
            .toggle
            .iter()
            .chain(&rows.channels)
            .chain(&rows.other)
            .map(|a| a.id)
            .collect();
        let mut expected = tab.actions();
        expected.sort_by_key(|a| format!("{a:?}"));
        let mut got = rendered.clone();
        got.sort_by_key(|a| format!("{a:?}"));
        assert_eq!(got, expected, "a verb the model offered reached no group");
        assert!(
            !rows.toggle.is_empty() && !rows.channels.is_empty(),
            "the fixture offers no toggle or no channels, so the grouping is untested: {rendered:?}"
        );
    }

    /// **With no beacon there are no update controls to render — and none are invented.**
    ///
    /// PR #120 removes the change controls rather than disabling them when the beacon cannot be
    /// asked, and this pane must not re-add a dead switch. The model is what removes them, so the
    /// assertion is that the pane's groups are empty of everything except the explainer.
    #[test]
    fn an_unreachable_beacon_leaves_no_switch_to_press() {
        let view = TrayView {
            running: true,
            update: None,
            ..TrayView::default()
        };
        let model = crate::window_model::build(&view);
        let tab = model
            .tab(crate::window_model::TabId::Settings)
            .expect("Settings");
        let rows = sort_rows(tab);

        assert!(
            rows.toggle.is_empty(),
            "a beacon nobody can ask got a switch"
        );
        assert!(
            rows.channels.is_empty(),
            "a beacon nobody can ask got a channel chooser"
        );
        assert!(
            !rows.other.is_empty(),
            "the tab offers nothing at all, so a person has no route to the explanation"
        );
    }

    /// **A settings file that cannot be read leaves the fields with nothing to edit, and says why.**
    ///
    /// The same rule one level down: a form over a file DIG cannot read would save into nothing.
    #[test]
    fn an_unreadable_settings_file_is_a_stated_state_not_an_empty_form() {
        let mut broken = FakeStore::holding(AgentConfig::default());
        broken.unreadable = Some("agent.json is not valid JSON".to_string());
        let session = Session::from_store(Some(std::sync::Arc::new(broken)));
        assert!(session.unreadable.is_some());

        let readable = session_over(FakeStore::holding(AgentConfig {
            node_url: Some("http://my.node".to_string()),
            ..AgentConfig::default()
        }));
        assert_eq!(readable.unreadable, None);
        assert_eq!(readable.draft(Setting::NodeUrl), "http://my.node");
    }

    /// **A host with nowhere to keep settings says so rather than offering a form.**
    #[test]
    fn a_host_with_no_settings_file_at_all_states_it() {
        let session = Session::from_store(None);
        assert_eq!(
            session.unreadable.as_deref(),
            Some(copy::settings::NO_CONFIG)
        );
    }

    /// **A save the store did not keep leaves the field showing what IS stored, and says nothing
    /// about having saved.**
    ///
    /// The pane-level half of `prefs::save`'s read-back, and the thing a person actually sees: the
    /// field snaps back to the stored value rather than keeping the typed one, so nobody walks away
    /// believing a node address is in force that is not. The honest store is the control — without
    /// it, a session that ALWAYS discarded what was typed would pass.
    #[test]
    fn a_save_that_did_not_land_is_not_drawn_as_a_save() {
        let mut lossy = FakeStore::holding(AgentConfig::default());
        lossy.writes_are_lost = true;
        let mut session = session_over(lossy);
        session.node.typed = "http://my.node:9778".to_string();
        session.save(Setting::NodeUrl, None);

        assert_eq!(
            session.draft(Setting::NodeUrl),
            "",
            "the field kept an address the settings file does not hold"
        );
        assert_eq!(session.config.node_url, None);

        let mut honest = session_over(FakeStore::holding(AgentConfig::default()));
        honest.node.typed = "http://my.node:9778".to_string();
        honest.save(Setting::NodeUrl, None);
        assert_eq!(honest.draft(Setting::NodeUrl), "http://my.node:9778");
        assert_eq!(
            honest.note(Setting::NodeUrl).as_deref(),
            Some(copy::settings::SAVED)
        );
    }

    /// **The escape hatch works from a REFUSED value, which is the state it exists for.**
    ///
    /// A person who typed something DIG will not accept is left with a field that will not save.
    /// "Go back to automatic" has to clear it regardless of what is in the box — a control that
    /// validated the current text first would refuse the very press that gets them out
    /// (`professional-ui`'s never-trap-the-user rule, on a form).
    #[test]
    fn the_way_back_to_automatic_works_even_when_the_field_is_invalid() {
        let mut session = session_over(FakeStore::holding(AgentConfig {
            node_url: Some("http://old.node".to_string()),
            ..AgentConfig::default()
        }));
        session.node.typed = "ftp://nonsense".to_string();
        session.save(Setting::NodeUrl, None);
        assert!(
            session.error(Setting::NodeUrl).is_some(),
            "the fixture's bad address was accepted, so this proves nothing"
        );

        session.act_locally(Local::AutomaticNode);
        assert_eq!(session.error(Setting::NodeUrl), None);
        assert_eq!(session.draft(Setting::NodeUrl), "");
        assert_eq!(session.config.node_url, None);
        assert_eq!(
            Setting::NodeUrl.effective(&session.config),
            crate::control::endpoint_ladder(None).join(", "),
            "clearing the address did not put DIG back on the automatic ladder"
        );
    }

    /// A session over `store`, as the pane holds one.
    fn session_over(store: FakeStore) -> Session {
        Session::from_store(Some(std::sync::Arc::new(store)))
    }

    /// Every string the whole pane painted, at `width`, with `view`'s facts and `session` seeded.
    ///
    /// The session is seeded so the test never reads the machine it runs on: the pane would
    /// otherwise open this developer's own `agent.json`, and the assertions would depend on it.
    fn painted_pane(view: &TrayView, session: Session, width: f32) -> Vec<String> {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let model = crate::window_model::build(view);
        let tab = model
            .tab(crate::window_model::TabId::Settings)
            .expect("Settings renders in every state")
            .clone();
        let facts = PaneFacts::of_tray(view);
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
                    egui::Area::new(egui::Id::new("settings-pane-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            ui.data_mut(|d| d.insert_temp(session_id(), session.clone()));
                            let column = egui::Rect::from_min_size(
                                screen.left_top(),
                                egui::Vec2::new(width - space::S5 * 2.0, f32::INFINITY),
                            );
                            let mut flow = Flow::new(ui, column, true);
                            draw(&mut flow, &t, &tab, &facts);
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

    /// **The whole pane, drawn: what it SAYS about updates comes from the beacon, and the remembered
    /// preference never reaches the screen.**
    ///
    /// The unit tests above pin the helpers; this one pins the assembled pane, which is where a
    /// wiring mistake would actually live. The fixture makes the two sources disagree as loudly as
    /// they can — `agent.json` remembers *enabled, nightly* while the beacon reports a schedule that
    /// was removed and a stable feed — so a card that read the config would say the opposite of what
    /// this asserts. Drawn at `SHELL_MIN`, so the narrow width is exercised at the same time.
    #[test]
    fn the_drawn_pane_reports_the_beacon_and_never_the_remembered_preference() {
        let view = TrayView {
            running: true,
            update: Some(beacon(false, true, UpdateChannel::Stable)),
            ..TrayView::default()
        };
        let session = session_over(FakeStore::holding(AgentConfig {
            auto_update: crate::auto_update::AutoUpdate {
                enabled: true,
                channel: UpdateChannel::Nightly,
            },
            ..AgentConfig::default()
        }));

        let said = painted_pane(&view, session, super::super::super::shell::SHELL_MIN);
        let all = said.join(" | ");
        assert!(
            all.contains("Updates off"),
            "the pane did not report a machine whose schedule is gone as off: {all}"
        );
        assert!(
            all.contains(UpdateChannel::Stable.display_name()),
            "the pane never named the channel the beacon is on: {all}"
        );
        assert!(
            all.contains(copy::settings::UPDATES_COST),
            "the elevation cost was not stated in the card: {all}"
        );
        // The remembered wish is `Nightly` and the beacon is on `Stable`. `Nightly` legitimately
        // appears as the OTHER channel's button, so the check is on the readout that states what
        // this machine follows — which must not have taken its value from the config.
        let following = said
            .iter()
            .position(|line| line == copy::settings::CHANNEL_LABEL)
            .map(|at| said[at + 1].clone())
            .expect("the card draws a 'Following' readout");
        assert_eq!(following, UpdateChannel::Stable.display_name());
    }

    /// **The whole pane draws both settings forms, with their costs and their escape hatches.**
    ///
    /// §5.3's requirement is that the setting be USER-FACING, so the check is that the control and
    /// its way back are actually painted — not that a function exists that could paint them.
    #[test]
    fn the_drawn_pane_offers_the_node_setting_and_a_way_back_to_automatic() {
        let view = TrayView {
            running: true,
            update: Some(beacon(false, false, UpdateChannel::Stable)),
            ..TrayView::default()
        };
        let said = painted_pane(
            &view,
            session_over(FakeStore::holding(AgentConfig::default())),
            super::super::super::shell::SHELL_MIN,
        )
        .join(" | ");

        for expected in [
            copy::settings::NODE_CARD,
            copy::settings::NODE_FIELD,
            copy::settings::NODE_COST,
            copy::settings::NODE_SAVE,
            copy::settings::NODE_AUTOMATIC,
            copy::settings::NODE_TEST,
            copy::settings::SHORTCUT_CARD,
            copy::settings::SHORTCUT_COST,
            copy::settings::SHORTCUT_DEFAULT,
        ] {
            assert!(said.contains(expected), "the pane never drew {expected:?}");
        }
        // What DIG will really dial, from the connector's own ladder rather than a sentence.
        assert!(
            said.contains(&crate::control::endpoint_ladder(None).join(", ")),
            "the pane did not say which addresses automatic actually means: {said}"
        );
    }

    /// **Typing withdraws the previous answer about that field.**
    ///
    /// A "Saved." line, an error, or a connection result left standing over a field somebody has
    /// since edited is a claim about a value that is no longer there.
    #[test]
    fn editing_a_field_withdraws_what_was_said_about_the_old_value() {
        let mut session = session_over(FakeStore::holding(AgentConfig::default()));
        session.node.saved = true;
        session.node.error = Some("something".to_string());
        session.tester.start(&egui::Context::default(), None);

        session.edited(Setting::NodeUrl);
        assert!(!session.node.saved);
        assert_eq!(session.node.error, None);
        assert_eq!(session.tester.state(), Probe::Idle);
        assert_eq!(session.note(Setting::NodeUrl), None);
    }
}
