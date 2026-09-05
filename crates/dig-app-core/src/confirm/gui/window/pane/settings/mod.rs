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

pub(crate) mod appearance;
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
use crate::collateral;
use crate::collateral::node::{
    BufferReading, BufferUnknown, CollateralBufferUnknownReason, CollateralFundingState,
    CollateralUnknown, MarginReading, NodeBuffer, RequirementReading,
};
use crate::config::AgentConfig;
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::mirror_advertise::{
    AdvertiseReading, AdvertiseUnknown, AdvertiseWriteReading, MirrorAdvertiseState,
};
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
    /// Choose how far over the collateral requirement this node posts, in basis points
    /// (dig-app#298).
    SetMargin(u64),
    /// Write the typed mirror advertise-URL override (dig-app#387).
    SaveAdvertise,
    /// Clear the mirror advertise-URL override, back to the node's derived default.
    AutomaticAdvertise,
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
    flow.gap(space::S4);
    // Above the margin chooser rather than below it: this card is the reason a person would touch
    // that chooser, and the figure it names is what the choice is weighed against.
    funding_card(flow, t, &mut session);
    flow.gap(space::S4);
    margin_card(flow, t, &mut session);
    flow.gap(space::S4);
    // Beside the margin rather than the connection card: both are about what makes THIS node's
    // mirror bonds actually count, where the connection card is about which node dig-app reads
    // through (dig-app#387).
    advertise_card(flow, t, &mut session);
    flow.gap(space::S4);
    // Last of the cards: it changes nothing but how the window looks, so it sits below the settings
    // that change what DIG does (dig_ecosystem#2997).
    appearance::card(flow, t);
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

/// The collateral safety-margin group: the choice, and what it costs right now (dig-app#298).
///
/// Laid out exactly like [`notifications_card`] — a chooser over presets, with the cost stated
/// above it — because a second layout for the same shape of control is the drift this design system
/// exists to end. The one addition is that the readouts are drawn from a
/// [`CostReading`](crate::collateral::CostReading), so an unknown cost is a `Value::Unknown`
/// carrying its reason and never a `0`.
fn margin_card(flow: &mut Flow, t: &Tokens, session: &mut Session) {
    let live = flow.live();
    let unreadable = session.unreadable.clone();
    // The node's margin, never a local copy: dig-app stores none (dig-app#302). Until a read
    // answers, there is no margin to draw a cost from, and the card says so rather than assuming the
    // shipped default — a margin shown from an assumption is a margin the node may not be applying.
    let margin_reading = session.margin_reading.clone();
    let margin = margin_reading.margin();
    // Counted from the node's own buffer answer, never from the length of dig-app's hosted-store
    // list. The list is keyed on `store_id`; the node posts per qualifying `(owner, store, root)`
    // pair, so one store serving two owners is one entry and two postings. Counting entries
    // understates the total, and understating money to be locked is the direction that costs an
    // operator an epoch.
    let reading = margin.map(|margin| {
        collateral::cost(
            margin,
            &session.requirement_reading,
            &session.buffer_reading,
        )
    });
    let options: Vec<Choice<Local>> = collateral::SAFETY_MARGIN_PRESETS_BP
        .iter()
        .map(|&bp| Choice {
            label: collateral::SafetyMargin { margin_bp: bp }.percent_label(),
            id: Local::SetMargin(bp),
        })
        .collect();
    // A margin that matches no preset selects NOTHING rather than the nearest one, and an UNREAD
    // margin selects nothing either: the chooser must not claim a value the node has not reported.
    let selected = margin.and_then(collateral::SafetyMargin::preset_index);
    let unknown_label = match margin {
        Some(margin) => margin.percent_label(),
        None => copy::settings::MARGIN_UNREAD.to_string(),
    };
    let note = session.margin.saved.then_some(copy::settings::SAVED);

    let hit = flow.place(|ui, at| {
        let mut hit = None;
        let height = card::interactive_card(
            ui,
            at,
            t,
            live,
            Some(copy::settings::MARGIN_CARD),
            |inner| {
                inner.place(|ui, at| (text::caption(ui, at, t, copy::settings::MARGIN_ABOUT), ()));
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

                for item in margin_readouts(reading.as_ref()) {
                    inner.place(|ui, at| (data::readout(ui, at, t, &item), ()));
                }
                inner.gap(space::S4);
                inner.place(|ui, at| (text::caption(ui, at, t, copy::settings::MARGIN_COST), ()));
                inner.gap(space::S3);
                hit = inner.place(|ui, at| {
                    select::select(
                        ui,
                        at,
                        t,
                        live,
                        &select::Select {
                            label: copy::settings::MARGIN_FIELD,
                            options: &options,
                            selected,
                            unknown: &unknown_label,
                            id: egui::Id::new("dig-settings-collateral-margin"),
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
    if let Some(Local::SetMargin(margin_bp)) = hit {
        session.act_locally(Local::SetMargin(margin_bp));
    }
}

/// The mirror advertise-URL group: what the node is about to publish, and letting a person change
/// it (dig-app#387).
///
/// Modelled on [`margin_card`] rather than [`setting_card`]: this setting is NODE-backed, not
/// file-backed, so it needs [`AdvertiseReading`]'s three-state honesty rather than [`Setting`]'s
/// stored/typed pair. It borrows [`setting_card`]'s [`Field`] because, unlike the margin, this is
/// free text rather than a preset choice — but it validates and writes through
/// [`Session::save_advertise`], never through [`prefs::save`], because nothing here touches
/// `agent.json`.
fn advertise_card(flow: &mut Flow, t: &Tokens, session: &mut Session) {
    let live = flow.live();
    let unreadable = session.unreadable.clone();
    let reading = session.advertise_reading.clone();
    let note = advertise_note(session.advertise.saved, session.advertise_requires_restart);

    let hit = flow.place(|ui, at| {
        let mut hit = None;
        let height = card::interactive_card(
            ui,
            at,
            t,
            live,
            Some(copy::settings::ADVERTISE_CARD),
            |inner| {
                inner.place(|ui, at| {
                    (
                        text::caption(ui, at, t, copy::settings::ADVERTISE_ABOUT),
                        (),
                    )
                });
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

                for item in advertise_readouts(&reading) {
                    inner.place(|ui, at| (data::readout(ui, at, t, &item), ()));
                }
                // Under the figures, not instead of them, and for the same reason
                // `funding_sentence` is drawn separately from `funding_readouts`: the sentence says
                // what the state MEANS, and `Value::Word` is for a short word, never a full
                // sentence.
                if let Some(sentence) = advertise_sentence(&reading) {
                    inner.gap(space::S3);
                    inner.place(|ui, at| (text::caption(ui, at, t, sentence), ()));
                }
                inner.gap(space::S4);
                inner
                    .place(|ui, at| (text::caption(ui, at, t, copy::settings::ADVERTISE_COST), ()));
                inner.gap(space::S3);

                let field = Field {
                    label: copy::settings::ADVERTISE_FIELD,
                    placeholder: copy::settings::ADVERTISE_PLACEHOLDER,
                    help: copy::settings::ADVERTISE_HELP,
                    error: session.advertise.error.clone(),
                    id: egui::Id::new("dig-settings-mirror-advertise"),
                };
                let before = session.advertise.typed.clone();
                inner.place(|ui, at| {
                    (
                        field::text_field(ui, at, t, live, &field, &mut session.advertise.typed),
                        (),
                    )
                });
                if session.advertise.typed != before {
                    // An answer about the address that WAS typed is worse than no answer at all --
                    // the same rule `setting_card` follows for the two file-backed fields.
                    session.advertise.saved = false;
                    session.advertise.error = None;
                }
                inner.gap(space::S3);

                let actions = [
                    (Local::SaveAdvertise, copy::settings::ADVERTISE_SAVE),
                    (
                        Local::AutomaticAdvertise,
                        copy::settings::ADVERTISE_AUTOMATIC,
                    ),
                ]
                .map(|(id, label)| Action {
                    label: label.to_string(),
                    weight: Weight::Ghost,
                    enabled: true,
                    id,
                    element: egui::Id::new(("dig-settings-control", label)),
                });
                hit = inner.place(|ui, at| action::buttons(ui, at, t, live, &actions));

                if let Some(note) = note {
                    inner.gap(space::S3);
                    inner.place(|ui, at| (text::caption(ui, at, t, note), ()));
                }
            },
        )
        .0;
        (height, hit)
    });
    if let Some(control) = hit {
        session.act_locally(control);
    }
}

/// The readouts the advertise card draws, for every state [`AdvertiseReading`] can be in.
///
/// Returned as a list rather than drawn here so the property that matters can be asserted
/// directly: **no state yields an address the node did not report.** A pending read and a read
/// that failed each produce exactly one [`Value::Unknown`] naming its own remedy — never a blank
/// field, which is the failure this whole card exists to replace.
fn advertise_readouts(reading: &AdvertiseReading) -> Vec<Readout> {
    match reading {
        AdvertiseReading::Pending => vec![Readout::new(
            copy::settings::ADVERTISE_EFFECTIVE,
            Value::Unknown(copy::settings::ADVERTISE_PENDING.to_string()),
        )],
        AdvertiseReading::Unknown(why) => vec![Readout::new(
            copy::settings::ADVERTISE_EFFECTIVE,
            Value::Unknown(why.remedy()),
        )],
        AdvertiseReading::Known(info) => {
            let mut rows = vec![Readout::new(
                copy::settings::ADVERTISE_EFFECTIVE,
                Value::Word(advertise_state_label(info.state).to_string()),
            )];
            // Empty in every state but the two publishing ones (see `AdvertiseInfo::urls`'s own
            // doc) -- so this never draws an empty address row for a state that has none to show.
            if !info.urls.is_empty() {
                rows.push(Readout::new(
                    copy::settings::ADVERTISE_URLS,
                    Value::Identifier(info.urls.join(", ")),
                ));
            }
            rows
        }
    }
}

/// The short badge word for each of dig-node#562's six outcomes -- a NOUN, never the sentence.
///
/// Exhaustive with no wildcard: a seventh state added upstream fails to compile here rather than
/// silently drawing whatever word a `_` arm happened to hold.
const fn advertise_state_label(state: MirrorAdvertiseState) -> &'static str {
    match state {
        MirrorAdvertiseState::AdvertisingOverride => "Your address",
        MirrorAdvertiseState::AdvertisingDerived => "Automatic",
        MirrorAdvertiseState::Off => "Off",
        MirrorAdvertiseState::NoPublicAddress => "No address yet",
        MirrorAdvertiseState::UncorroboratedAddress => "Confirming",
        MirrorAdvertiseState::NoRelay => "No relay path",
    }
}

/// The sentence explaining what a KNOWN state means. `None` for `Pending`/`Unknown`, whose own
/// readout has already said its piece via [`AdvertiseUnknown::remedy`].
///
/// Exhaustive with no wildcard, for the reason [`advertise_state_label`] is: a seventh state must
/// fail to compile here rather than silently reading as its nearest neighbour -- which matters
/// most for [`MirrorAdvertiseState::UncorroboratedAddress`], the one state that must never read as
/// a fault (see the module's own doc on it).
fn advertise_sentence(reading: &AdvertiseReading) -> Option<&'static str> {
    let AdvertiseReading::Known(info) = reading else {
        return None;
    };
    Some(match info.state {
        MirrorAdvertiseState::AdvertisingOverride => copy::settings::ADVERTISE_STATE_OVERRIDE,
        MirrorAdvertiseState::AdvertisingDerived => copy::settings::ADVERTISE_STATE_DERIVED,
        MirrorAdvertiseState::Off => copy::settings::ADVERTISE_STATE_OFF,
        MirrorAdvertiseState::NoPublicAddress => copy::settings::ADVERTISE_STATE_NO_PUBLIC_ADDRESS,
        MirrorAdvertiseState::UncorroboratedAddress => {
            copy::settings::ADVERTISE_STATE_UNCORROBORATED
        }
        MirrorAdvertiseState::NoRelay => copy::settings::ADVERTISE_STATE_NO_RELAY,
    })
}

/// The note under the controls: the honest difference between "saved" and "saved and LIVE".
///
/// Never collapsed to a bare "Saved." when a restart is owed -- see
/// [`dig_node_control_interface::results::SetMirrorAdvertiseUrlsResult::requires_restart`]'s own
/// doc for why a surface that cannot tell the two apart tells an operator their node is publishing
/// an address it has not applied yet.
fn advertise_note(saved: bool, requires_restart: Option<bool>) -> Option<&'static str> {
    if !saved {
        return None;
    }
    Some(match requires_restart {
        Some(true) => copy::settings::ADVERTISE_SAVED_NEEDS_RESTART,
        Some(false) => copy::settings::ADVERTISE_SAVED_LIVE,
        // `write_advertise` never sets `saved` without also recording the restart flag in the SAME
        // branch, so this is unreachable in practice -- defensive rather than a state this app can
        // actually produce.
        None => copy::settings::SAVED,
    })
}

/// Draw what the node says about its own $DIG (dig-app#306).
///
/// # Why this is a readout and not a control
///
/// There is nothing to press. The recommendation is the node's, the balance is the node's, and the
/// verdict between them is the node's — this card's whole job is to make all three visible to the
/// person who has to act on them. A control here would be an action over money the app cannot take.
///
/// # Why it shows its working
///
/// A calculated buffer whose calculation is hidden is just a louder alarm. So the terms travel with
/// the total: the pairs served, the per-store requirement, the margin in force, and the horizon —
/// each **from the node's payload**, never from a constant here. The same buffer over a different
/// horizon is a different claim, and a horizon this app supplied would be this app's claim.
fn funding_card(flow: &mut Flow, t: &Tokens, session: &mut Session) {
    let unreadable = session.unreadable.clone();
    let reading = session.buffer_reading.clone();
    flow.place(|ui, at| {
        let height = card::card(ui, at, t, Some(copy::settings::FUNDING_CARD), |inner| {
            inner.place(|ui, at| (text::caption(ui, at, t, copy::settings::FUNDING_ABOUT), ()));
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

            for item in funding_readouts(&reading) {
                inner.place(|ui, at| (data::readout(ui, at, t, &item), ()));
            }

            // Under the figures, not instead of them: the sentence says what the state MEANS, and a
            // person who already understands the numbers should not have to read past it to see
            // them. `None` for every state with no figures — an unknown has already said its piece.
            if let Some(sentence) = funding_sentence(&reading) {
                inner.gap(space::S3);
                inner.place(|ui, at| (text::caption(ui, at, t, sentence), ()));
            }
        });
        (height, ())
    });
}

/// The readouts the funding card draws, for every state the reading can be in.
///
/// Returned as a list rather than drawn here so the property that matters can be asserted directly:
/// **no state yields a numeral the node did not supply.** A pending read, a node that cannot say,
/// and a read that failed each produce exactly one [`Value::Unknown`] naming its own remedy — never
/// a zero, and never a figure this app assembled.
fn funding_readouts(reading: &BufferReading) -> Vec<Readout> {
    let buffer = match reading {
        BufferReading::Pending => {
            return vec![unknown_funding(copy::settings::FUNDING_PENDING)];
        }
        BufferReading::Unknown(BufferUnknown::NodeCannotSay(_)) => {
            return vec![unknown_funding(copy::settings::FUNDING_NODE_CANNOT_SAY)];
        }
        BufferReading::Unknown(BufferUnknown::ReadFailed(_)) => {
            return vec![unknown_funding(copy::settings::FUNDING_UNREAD)];
        }
        BufferReading::Known(buffer) => buffer,
    };

    let mut rows = vec![Readout::new(
        copy::settings::FUNDING_STATE,
        Value::Word(funding_label(buffer.funding_state).to_string()),
    )];

    // Whether to ask for money is the NODE's verdict, never a comparison made here. The two axes
    // move independently in the contract's own KAT, so a local `recommended > spendable` test can
    // ask a `Funded` node for more $DIG, or stay silent on a node that says it is short. That is the
    // same rival-derivation defect this ticket deleted from the runway, and it is worth nothing to
    // remove it from one function and leave it in the next.
    if names_an_amount_to_add(buffer.funding_state) {
        rows.push(dig_row(
            copy::settings::FUNDING_ADD,
            buffer.add_dig_base_units(),
        ));
    }
    rows.push(dig_row(
        copy::settings::FUNDING_RECOMMENDED,
        buffer.recommended_buffer_dig_base_units,
    ));
    rows.push(dig_row(
        copy::settings::FUNDING_SPENDABLE,
        buffer.spendable_dig_base_units,
    ));
    rows.push(Readout::new(
        copy::settings::FUNDING_PAIRS,
        Value::Word(buffer.pairs_served_by_this_node.to_string()),
    ));
    rows.push(dig_row(
        copy::settings::FUNDING_REQUIRED,
        buffer.required_per_store_dig_base_units,
    ));
    rows.push(Readout::new(
        copy::settings::FUNDING_MARGIN,
        Value::Word(buffer.margin.percent_label()),
    ));
    rows.push(Readout::new(
        copy::settings::FUNDING_HORIZON,
        Value::Word(horizon_phrase(buffer.horizon_epochs)),
    ));
    rows
}

/// One unknown funding row: a reason, and deliberately no figure beside it.
fn unknown_funding(why: &str) -> Readout {
    Readout::new(
        copy::settings::FUNDING_STATE,
        Value::Unknown(why.to_string()),
    )
}

/// A $DIG amount row, through [`crate::amount`] — which knows $DIG is a CAT at three decimals.
fn dig_row(label: &str, base_units: u64) -> Readout {
    Readout::new(
        label,
        Value::Measure {
            amount: crate::amount::format_dig(base_units),
            unit: "$DIG".to_string(),
        },
    )
}

/// The sentence explaining a known state, or `None` when the reading names no state.
///
/// `None` for pending and for both unknowns, where [`funding_readouts`] has already said its piece:
/// a reason drawn twice reads as two different facts.
const fn funding_sentence(reading: &BufferReading) -> Option<&'static str> {
    match reading {
        BufferReading::Known(buffer) => Some(match buffer.funding_state {
            CollateralFundingState::ShortNow => copy::settings::FUNDING_SHORT_NOW,
            CollateralFundingState::DangerouslyLow => copy::settings::FUNDING_DANGEROUSLY_LOW,
            CollateralFundingState::BelowRecommendedBuffer => copy::settings::FUNDING_BELOW_BUFFER,
            CollateralFundingState::Funded => copy::settings::FUNDING_FUNDED,
        }),
        BufferReading::Pending | BufferReading::Unknown(_) => None,
    }
}

/// Whether this state asks the operator for more $DIG.
///
/// A total match on the node's verdict, so a fifth state is a compile error rather than a state that
/// silently inherits an answer about money.
///
/// `Funded` is the only silent one. The other three each name a gap the node itself decided exists —
/// including `BelowRecommendedBuffer`, which is covered every epoch but short of the cushion, and is
/// the reason this is not simply "the shortfall states": a person cannot close a gap nobody showed
/// them.
///
/// The AMOUNT is still `recommended - spendable`, which is a subtraction between two figures the node
/// supplied against its own authoritative total. Only the decision to ask at all moved.
const fn names_an_amount_to_add(state: CollateralFundingState) -> bool {
    match state {
        CollateralFundingState::ShortNow
        | CollateralFundingState::DangerouslyLow
        | CollateralFundingState::BelowRecommendedBuffer => true,
        CollateralFundingState::Funded => false,
    }
}

/// The short label each state is named by, beside the figures.
///
/// A total match, so a fifth state added to the contract is a compile error here rather than a state
/// that silently borrows another's words.
///
/// `BelowRecommendedBuffer` deliberately reads as covered rather than as a warning: it describes a
/// missing cushion on a node that IS covered, and dressing a cushion as a shortfall is how the two
/// states that really are shortfalls stop being read.
const fn funding_label(state: CollateralFundingState) -> &'static str {
    match state {
        CollateralFundingState::ShortNow => "Short now",
        CollateralFundingState::DangerouslyLow => "Low for next epoch",
        CollateralFundingState::BelowRecommendedBuffer => "Covered, no cushion",
        CollateralFundingState::Funded => "Funded",
    }
}

/// `1 epoch` / `4 epochs`, from the node's horizon — so no sentence carries its own plural and no
/// constant here supplies the number.
fn horizon_phrase(epochs: u32) -> String {
    match epochs {
        1 => "1 epoch".to_string(),
        n => format!("{n} epochs"),
    }
}

/// The readouts for the margin card: the cost when a margin was read, and otherwise the reason the
/// margin itself is not known.
///
/// `None` means the NODE's margin could not be read at all, which is a different failure from a
/// known margin with an unknown price — and it must not borrow the latter's sentence, because that
/// one promises the choice is saved and applied. Nothing here can promise that when nothing has been
/// read.
fn margin_readouts(reading: Option<&collateral::CostReading>) -> Vec<Readout> {
    match reading {
        Some(reading) => cost_readouts(reading),
        None => vec![Readout::new(
            copy::settings::MARGIN_EFFECTIVE,
            Value::Unknown(copy::settings::MARGIN_NOT_READ.to_string()),
        )],
    }
}

/// The sentence a person reads when there is no cost figure — the REASON's own remedy, not a
/// summary of it.
///
/// Exhaustive at every level, with no wildcard anywhere on the path. That is the whole point of
/// dig-app#325: the reasons were split apart because "your node cannot read its own balance",
/// "the census has not run yet" and "you are short" need a wallet checked, patience, and money
/// respectively — and a `_` arm here would quietly hand all three the same words again the next
/// time a reason is added upstream.
fn cost_unknown_sentence(why: &collateral::CostUnknown) -> &'static str {
    match why {
        // The named fallback. Nothing produces it today; it exists so a future state with no
        // remedy of its own lands here BY NAME rather than by collapse.
        collateral::CostUnknown::NoRequirement => copy::settings::MARGIN_NO_REQUIREMENT,
        collateral::CostUnknown::RequirementUnknown(reason) => reason.remedy(),
        collateral::CostUnknown::PairsUnknown(why) => buffer_unknown_sentence(why),
    }
}

/// The sentence for a buffer read that could not answer.
///
/// The same defect as the requirement path had, in the same card: a node that cannot enumerate its
/// stores and a node that cannot read its own $DIG are different problems with different remedies,
/// and one sentence for both sends a person to the wrong place.
fn buffer_unknown_sentence(why: &BufferUnknown) -> &'static str {
    match why {
        // A control call fails identically whichever collateral verb it names, so these sentences
        // are written once, on the reason itself.
        BufferUnknown::ReadFailed(reason) => reason.remedy(),
        BufferUnknown::NodeCannotSay(reason) => match reason {
            CollateralBufferUnknownReason::RequirementUnknown => {
                copy::settings::MARGIN_BUFFER_NO_REQUIREMENT
            }
            CollateralBufferUnknownReason::ServedSetUnknown => copy::settings::MARGIN_NO_PAIRS,
            CollateralBufferUnknownReason::ReclaimStateUnknown => {
                copy::settings::MARGIN_BUFFER_NO_RECLAIM
            }
            CollateralBufferUnknownReason::BalanceUnknown => {
                copy::settings::MARGIN_BUFFER_NO_BALANCE
            }
        },
    }
}

/// The readouts a cost reading produces — the figures when there are figures, and the reason when
/// there is not.
///
/// Returned as a list rather than drawn here so it can be asserted directly: the guard that matters
/// is that no state yields a numeral it has not been told, and that is a property of the values.
fn cost_readouts(reading: &collateral::CostReading) -> Vec<Readout> {
    match reading {
        collateral::CostReading::Pending => vec![Readout::new(
            copy::settings::MARGIN_EFFECTIVE,
            Value::Unknown(copy::settings::MARGIN_PENDING.to_string()),
        )],
        collateral::CostReading::Unknown(why) => vec![Readout::new(
            copy::settings::MARGIN_EFFECTIVE,
            Value::Unknown(cost_unknown_sentence(why).to_string()),
        )],
        collateral::CostReading::Known(cost) => vec![
            Readout::new(
                copy::settings::MARGIN_EFFECTIVE,
                Value::Measure {
                    amount: crate::amount::format_dig(cost.extra_locked_dig_base_units),
                    unit: "$DIG".to_string(),
                },
            ),
            Readout::new(
                copy::settings::MARGIN_TOTAL,
                Value::Measure {
                    amount: crate::amount::format_dig(cost.total_posted_dig_base_units),
                    unit: "$DIG".to_string(),
                },
            ),
        ],
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
/// How this pane reaches the node's collateral settings.
///
/// Three function pointers rather than three direct calls, for the reason
/// [`NodeHostedStores`](crate::hosted_stores::NodeHostedStores) injects its token reader: without
/// it, constructing a `Session` in a test opens a real socket to whatever node happens to be running
/// on the developer's machine — so the suite would be slow, flaky, and dependent on a machine's
/// state rather than on the code.
///
/// It is a struct of `fn` pointers and not a trait object so [`Session`] stays `Clone` and `'static`,
/// which is what lets egui hold it in its temporary data between frames.
#[derive(Clone, Copy)]
struct CollateralSeam {
    read_margin: fn(Option<&str>) -> MarginReading,
    read_requirement: fn(Option<&str>) -> RequirementReading,
    read_buffer: fn(Option<&str>) -> BufferReading,
    write_margin: fn(Option<&str>, u64) -> MarginReading,
}

impl Default for CollateralSeam {
    /// The real control plane — what every shipped surface uses.
    fn default() -> Self {
        Self {
            read_margin: prefs::read_margin,
            read_requirement: prefs::read_requirement,
            read_buffer: prefs::read_buffer,
            write_margin: prefs::write_margin,
        }
    }
}

/// How this pane reaches the node's mirror advertise-URL override (dig-app#387) — the same
/// injectable-seam shape [`CollateralSeam`] uses, and for the same reason: a test that constructed
/// a [`Session`] through the real control plane would open a socket to whatever node happens to be
/// running on the developer's machine.
#[derive(Clone, Copy)]
struct AdvertiseSeam {
    read: fn(Option<&str>) -> AdvertiseReading,
    write: fn(Option<&str>, Option<Vec<String>>) -> AdvertiseWriteReading,
}

impl Default for AdvertiseSeam {
    /// The real control plane — what every shipped surface uses.
    fn default() -> Self {
        Self {
            read: prefs::read_advertise,
            write: prefs::write_advertise,
        }
    }
}

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
    /// The margin chooser's own "Saved." state — a choice, so only the confirmation half of
    /// [`FieldState`] is used, exactly as for the notification switch.
    margin: FieldState,
    /// The margin **as the node reports it**. dig-app keeps no copy of its own (dig-app#302), so
    /// this is a reading rather than a value: before the first read answers it is
    /// [`Pending`](MarginReading::Pending), and a node that cannot serve the verb leaves it
    /// [`Unknown`](MarginReading::Unknown) with the reason attached.
    margin_reading: MarginReading,
    /// This epoch's requirement, **as the node reports it**. Read beside the margin and over the
    /// same ladder, because the two are shown together and a card holding one without the other can
    /// state neither the margin nor its price.
    requirement_reading: RequirementReading,
    /// The node's recommended $DIG buffer and its funding position against it, **as the node
    /// reports them**. Nothing here is derived: the recommendation rests on the pairs this node
    /// serves, on collateral it has not yet reclaimed, and on a horizon it chose, and a figure
    /// dig-app assembled instead would be strictly smaller.
    buffer_reading: BufferReading,
    /// How the three readings above are obtained and how a new margin is applied.
    collateral: CollateralSeam,
    /// The notification switch's own "Saved." state. It has no typed value and no error — a choice
    /// cannot be malformed — so only the confirmation half of [`FieldState`] is used.
    notifications: FieldState,
    /// The mirror advertise-URL field's own typed draft, error and "Saved." state (dig-app#387).
    advertise: FieldState,
    /// What the node is about to publish, **as the node reports it**. dig-app keeps no copy of its
    /// own — the same discipline [`margin_reading`](Self::margin_reading) follows, and for the
    /// same money-honesty reason: the node is the one process that can discover, corroborate, and
    /// advertise its own address.
    advertise_reading: AdvertiseReading,
    /// Whether the last write THIS SESSION made is live yet, or needs a restart. `None` before any
    /// write — never assumed either way, per
    /// [`dig_node_control_interface::results::SetMirrorAdvertiseUrlsResult::requires_restart`]'s
    /// own doc.
    advertise_requires_restart: Option<bool>,
    /// How the advertise reading above is obtained and how a new override is applied.
    advertise_seam: AdvertiseSeam,
    tester: probe::Tester,
}

/// One field's typed value and what last happened to it.
#[derive(Clone, Default)]
struct FieldState {
    typed: String,
    error: Option<String>,
    saved: bool,
}

/// Which collateral answers a PREVIEW should draw the two collateral cards from.
///
/// Every state the cards can be in, named, so the gallery photographs them deliberately rather than
/// depending on whatever node happens to run on the machine taking the picture. A screenshot of the
/// unknown state taken because no node was running is not evidence that the unknown state renders
/// correctly — it is evidence that a machine had no node.
///
/// One enum for both cards because they share one `Session`: seeding them separately would mean
/// the second seed overwrote the first, and a preview that silently drew a state nobody asked for is
/// the false-picture failure this type exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollateralPreview {
    /// The node serves every verb: a margin, a priced requirement, and a funded position.
    Priced,
    /// The node serves the margin but cannot state the requirement — the case every node is in
    /// today, and the one the honest-unknown rule exists for.
    MarginWithoutRequirement,
    /// The node serves nothing. The margin itself is unread and no funding figure exists.
    Unread,
    /// The node cannot cover the current epoch.
    FundingShortNow,
    /// The node covers this epoch but not the next at the escalation ceiling.
    FundingDangerouslyLow,
    /// The node is covered and holds less than its own recommended cushion.
    FundingBelowBuffer,
    /// The buffer read is still in flight.
    FundingPending,
    /// The node answered and named one of its OWN facts as missing — a different remedy from a
    /// read that failed, and photographed separately for exactly that reason.
    FundingNodeCannotSay,
}

/// Seed a settings session for a preview, so the margin card can be photographed in `state`.
///
/// Written into egui's temporary store BEFORE the first frame, exactly as the wallet offer field is,
/// because a committed screenshot must never be taken after synthetic input. The session it plants
/// carries a seam of pure functions, so drawing the pane opens no socket.
pub fn seed_collateral_preview(ctx: &egui::Context, state: CollateralPreview) {
    use crate::collateral::node::{
        CollateralBufferUnknownReason, CollateralUnknown, EpochRequirement,
    };
    use crate::collateral::SafetyMargin;

    /// A priced epoch, shared by every preview whose requirement is known.
    fn priced() -> RequirementReading {
        RequirementReading::Known(EpochRequirement {
            epoch: 7,
            protocol_version: 1,
            required_per_store_dig_base_units: 5_000,
            stores: 40,
            owners: 1_000,
            multiplier_micros: 1_000_000,
            handicap_dig_base_units: 0,
        })
    }

    let seam = match state {
        CollateralPreview::Priced => CollateralSeam {
            read_margin: |_| MarginReading::Known(SafetyMargin::default()),
            read_requirement: |_| priced(),
            read_buffer: |_| funding_fixture(CollateralFundingState::Funded),
            write_margin: |_, bp| MarginReading::Known(SafetyMargin::of_basis_points(bp)),
        },
        CollateralPreview::MarginWithoutRequirement => CollateralSeam {
            read_margin: |_| MarginReading::Known(SafetyMargin::default()),
            read_requirement: |_| RequirementReading::Unknown(CollateralUnknown::NotCensused),
            read_buffer: |_| {
                BufferReading::Unknown(BufferUnknown::NodeCannotSay(
                    CollateralBufferUnknownReason::RequirementUnknown,
                ))
            },
            write_margin: |_, bp| MarginReading::Known(SafetyMargin::of_basis_points(bp)),
        },
        CollateralPreview::Unread => CollateralSeam {
            read_margin: |_| MarginReading::Unknown(CollateralUnknown::NodeCannotRead),
            read_requirement: |_| RequirementReading::Unknown(CollateralUnknown::NodeCannotRead),
            read_buffer: |_| {
                BufferReading::Unknown(BufferUnknown::ReadFailed(CollateralUnknown::NodeCannotRead))
            },
            write_margin: |_, _| MarginReading::Unknown(CollateralUnknown::NodeCannotRead),
        },
        CollateralPreview::FundingShortNow => {
            funding_seam(|_| funding_fixture(CollateralFundingState::ShortNow))
        }
        CollateralPreview::FundingDangerouslyLow => {
            funding_seam(|_| funding_fixture(CollateralFundingState::DangerouslyLow))
        }
        CollateralPreview::FundingBelowBuffer => {
            funding_seam(|_| funding_fixture(CollateralFundingState::BelowRecommendedBuffer))
        }
        CollateralPreview::FundingPending => funding_seam(|_| BufferReading::Pending),
        CollateralPreview::FundingNodeCannotSay => funding_seam(|_| {
            BufferReading::Unknown(BufferUnknown::NodeCannotSay(
                CollateralBufferUnknownReason::ReclaimStateUnknown,
            ))
        }),
    };
    // A store in memory rather than `None`: with no store the session is in its
    // cannot-read-the-settings-file state and every card draws a banner instead of its body, so a
    // picture taken that way would show an error while claiming to show the collateral cards.
    //
    // The advertise seam here is the fixed `no_node_advertise_seam` fixture, never the real one:
    // these previews are about the COLLATERAL cards, and giving them the real control plane would
    // reintroduce the exact real-socket-in-a-preview defect this whole injectable-seam design
    // exists to avoid. `seed_advertise_preview` is where the advertise card gets its own fixtures.
    let session = Session::from_store_through(
        Some(std::sync::Arc::new(prefs::PreviewStore)),
        seam,
        no_node_advertise_seam(),
    );
    ctx.data_mut(|d| d.insert_temp(session_id(), session));
}

/// A seam whose margin and requirement are answered and whose buffer is `buffer`.
///
/// Takes a `fn` rather than a value because [`CollateralSeam`] holds function pointers, which
/// cannot close over anything — the preview state has to be chosen at the call site and baked into
/// the function itself.
fn funding_seam(buffer: fn(Option<&str>) -> BufferReading) -> CollateralSeam {
    CollateralSeam {
        read_margin: |_| MarginReading::Known(crate::collateral::SafetyMargin::default()),
        read_requirement: |_| {
            RequirementReading::Known(crate::collateral::node::EpochRequirement {
                epoch: 7,
                protocol_version: 1,
                required_per_store_dig_base_units: 5_000,
                stores: 40,
                owners: 1_000,
                multiplier_micros: 1_000_000,
                handicap_dig_base_units: 0,
            })
        },
        read_buffer: buffer,
        write_margin: |_, bp| {
            MarginReading::Known(crate::collateral::SafetyMargin::of_basis_points(bp))
        },
    }
}

/// A complete node buffer answer in `state`, for the previews.
///
/// The spendable balance moves with the state so each picture shows the figures that state would
/// really carry: a funded node has no "Add" row, and a short one does.
///
/// `pairs_served_by_this_node` is 23 — deliberately not a plausible length for this preview's store
/// list, so a picture drawn from the wrong count is visibly wrong rather than merely different.
fn funding_fixture(state: CollateralFundingState) -> BufferReading {
    let spendable = match state {
        CollateralFundingState::ShortNow => 40_000,
        CollateralFundingState::DangerouslyLow => 118_000,
        CollateralFundingState::BelowRecommendedBuffer => 132_000,
        CollateralFundingState::Funded => 190_000,
    };
    BufferReading::Known(NodeBuffer {
        epoch: 7,
        protocol_version: 1,
        funding_state: state,
        recommended_buffer_dig_base_units: 148_000,
        spendable_dig_base_units: spendable,
        pairs_served_by_this_node: 23,
        required_per_store_dig_base_units: 5_000,
        margin: crate::collateral::SafetyMargin::default(),
        overlap_dig_base_units: 12_500,
        escalation_headroom_dig_base_units: 19_450,
        horizon_epochs: 3,
        escalation_ceiling_micros: 1_500_000,
    })
}

/// The advertise seam every COLLATERAL preview is seeded with: a fixed, instant "no node
/// connected" answer.
///
/// Those previews photograph the margin and funding cards, not the advertise card, so they get the
/// cheapest honest fixture rather than the real control plane — which would open a real socket in
/// a preview binary, exactly the defect the seam types exist to design out.
fn no_node_advertise_seam() -> AdvertiseSeam {
    AdvertiseSeam {
        read: |_| AdvertiseReading::Unknown(AdvertiseUnknown::NoNode),
        write: |_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode),
    }
}

/// The collateral seam every ADVERTISE preview is seeded with — the mirror of
/// [`no_node_advertise_seam`], for the same reason: [`seed_advertise_preview`] photographs the
/// advertise card, so the margin and funding cards it shares a [`Session`] with get the cheapest
/// honest fixture rather than [`CollateralSeam::default`]'s real sockets.
fn no_node_collateral_seam() -> CollateralSeam {
    CollateralSeam {
        read_margin: |_| MarginReading::Unknown(CollateralUnknown::NodeCannotRead),
        read_requirement: |_| RequirementReading::Unknown(CollateralUnknown::NodeCannotRead),
        read_buffer: |_| {
            BufferReading::Unknown(BufferUnknown::ReadFailed(CollateralUnknown::NodeCannotRead))
        },
        write_margin: |_, _| MarginReading::Unknown(CollateralUnknown::NodeCannotRead),
    }
}

/// Which state the advertise card's preview should draw (dig-app#387) — named so the gallery
/// photographs dig-node#562's six outcomes deliberately, the same discipline [`CollateralPreview`]
/// applies to the margin and funding cards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvertisePreview {
    /// Publishing the operator's own override.
    Override,
    /// Publishing the node's own discovered address.
    Derived,
    /// An override is set, but none of it could be published.
    Off,
    /// No override, and the node does not yet know a public address.
    NoPublicAddress,
    /// One source has reported a public address and nothing has confirmed it yet.
    Uncorroborated,
    /// A public address is known, but no relay path is held.
    NoRelay,
    /// The first read has not answered yet.
    Pending,
    /// The node is too old to know about a mirror advertise-URL override.
    Unread,
}

/// Seed a settings session for a preview, so the advertise card can be photographed in `state`
/// without depending on a real node's actual configuration.
///
/// Written into egui's temporary store before the first frame, exactly as
/// [`seed_collateral_preview`] is, because a committed screenshot must never be taken after
/// synthetic input. The collateral seam here is fixed rather than real, for the same reason the
/// advertise seam is fixed in [`seed_collateral_preview`]: this picture is about the advertise
/// card, and a real socket in either direction would make the OTHER cards flaky or slow instead.
pub fn seed_advertise_preview(ctx: &egui::Context, state: AdvertisePreview) {
    /// A known reading for `state`, publishing `urls` — or, with `operator_set`, holding an
    /// override even though nothing in it is publishable ([`MirrorAdvertiseState::Off`]).
    ///
    /// A free function rather than a value built once and captured: [`AdvertiseSeam::read`] is a
    /// plain `fn` pointer, which — like [`CollateralSeam`]'s — cannot close over anything, so each
    /// arm below calls this with its own literal arguments instead of branching on a captured
    /// reading.
    fn info(state: MirrorAdvertiseState, urls: &[&str], operator_set: bool) -> AdvertiseReading {
        AdvertiseReading::Known(crate::mirror_advertise::AdvertiseInfo {
            urls: urls.iter().map(|u| u.to_string()).collect(),
            operator_override: operator_set.then(|| urls.iter().map(|u| u.to_string()).collect()),
            state,
        })
    }

    /// [`Off`](MirrorAdvertiseState::Off): an override is held, but nothing in it publishes.
    fn off() -> AdvertiseReading {
        let AdvertiseReading::Known(mut held) = info(MirrorAdvertiseState::Off, &[], true) else {
            unreachable!("info() always returns Known");
        };
        held.operator_override = Some(vec!["ftp://unusable.example".to_string()]);
        AdvertiseReading::Known(held)
    }

    let seam = match state {
        AdvertisePreview::Override => AdvertiseSeam {
            read: |_| {
                info(
                    MirrorAdvertiseState::AdvertisingOverride,
                    &["dig://203.0.113.7:9776"],
                    true,
                )
            },
            write: |_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode),
        },
        AdvertisePreview::Derived => AdvertiseSeam {
            read: |_| {
                info(
                    MirrorAdvertiseState::AdvertisingDerived,
                    &["dig://198.51.100.42:9776"],
                    false,
                )
            },
            write: |_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode),
        },
        AdvertisePreview::Off => AdvertiseSeam {
            read: |_| off(),
            write: |_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode),
        },
        AdvertisePreview::NoPublicAddress => AdvertiseSeam {
            read: |_| info(MirrorAdvertiseState::NoPublicAddress, &[], false),
            write: |_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode),
        },
        AdvertisePreview::Uncorroborated => AdvertiseSeam {
            read: |_| info(MirrorAdvertiseState::UncorroboratedAddress, &[], false),
            write: |_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode),
        },
        AdvertisePreview::NoRelay => AdvertiseSeam {
            read: |_| info(MirrorAdvertiseState::NoRelay, &[], false),
            write: |_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode),
        },
        AdvertisePreview::Pending => AdvertiseSeam {
            read: |_| AdvertiseReading::Pending,
            write: |_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode),
        },
        AdvertisePreview::Unread => AdvertiseSeam {
            read: |_| AdvertiseReading::Unknown(AdvertiseUnknown::NotSupported),
            write: |_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode),
        },
    };
    let session = Session::from_store_through(
        Some(std::sync::Arc::new(prefs::PreviewStore)),
        no_node_collateral_seam(),
        seam,
    );
    ctx.data_mut(|d| d.insert_temp(session_id(), session));
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
        Self::from_store_through(store, CollateralSeam::default(), AdvertiseSeam::default())
    }

    /// A session over `store`, reaching the node through `collateral` and `advertise`.
    ///
    /// Split from [`from_store`](Self::from_store) so a test can present its own node without a
    /// socket; every shipped caller goes through the default seams.
    fn from_store_through(
        store: Option<std::sync::Arc<dyn ConfigStore>>,
        collateral: CollateralSeam,
        advertise: AdvertiseSeam,
    ) -> Self {
        let read = match &store {
            None => Err(copy::settings::NO_CONFIG.to_string()),
            Some(store) => store.read(),
        };
        let (config, unreadable) = match read {
            Ok(config) => (config, None),
            Err(why) => (AgentConfig::default(), Some(why)),
        };
        let endpoint = config.node_url.as_deref();
        let read_margin = (collateral.read_margin)(endpoint);
        let read_requirement = (collateral.read_requirement)(endpoint);
        let read_buffer = (collateral.read_buffer)(endpoint);
        let read_advertise = (advertise.read)(endpoint);
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
            margin: FieldState::default(),
            // Asked once when the session is created, not on every frame: the pane redraws many
            // times a second and a control call per frame would hammer the node for a value that
            // changes only when somebody presses this chooser.
            margin_reading: read_margin,
            requirement_reading: read_requirement,
            buffer_reading: read_buffer,
            collateral,
            advertise: FieldState {
                // Seeded from the OPERATOR's override, never the derived address: the field is
                // where a person's own choice lives, and drawing the derived value here would make
                // "automatic" look like a typed override nobody entered.
                typed: read_advertise
                    .info()
                    .and_then(|info| info.operator_override.as_ref())
                    .and_then(|urls| urls.first())
                    .cloned()
                    .unwrap_or_default(),
                ..FieldState::default()
            },
            advertise_reading: read_advertise,
            advertise_requires_restart: None,
            advertise_seam: advertise,
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
            Local::SetMargin(margin_bp) => self.save_margin(margin_bp),
            Local::SaveAdvertise => self.save_advertise(),
            // The escape hatch out of a bad address, same rule as `AutomaticNode`: always
            // reachable, never gated on what is currently typed.
            Local::AutomaticAdvertise => self.write_advertise(None),
            // Handled by [`act`], which holds the context it needs. An arm rather than a catch-all
            // so a control added later cannot quietly fall through to doing nothing.
            Local::TestNode => {}
        }
    }

    /// Validate the typed mirror advertise-URL override, then set it on the node.
    ///
    /// A value [`mirror_advertise::looks_like_a_url`] refuses is reported on the field and never
    /// reaches the node — the same refuse-before-it-reaches-the-write rule [`Self::save`] follows
    /// for the two file-backed settings. An emptied field is the "use automatic" request, not
    /// `Some(vec![String::new()])`, which the node would refuse as ambiguous (see
    /// [`crate::mirror_advertise`]'s module doc) — so a person who clears the box and presses Save
    /// gets exactly what [`Local::AutomaticAdvertise`] would have given them.
    fn save_advertise(&mut self) {
        let typed = self.advertise.typed.trim().to_string();
        if typed.is_empty() {
            self.write_advertise(None);
            return;
        }
        if let Err(problem) = crate::mirror_advertise::looks_like_a_url(&typed) {
            self.advertise.error = Some(problem.to_string());
            self.advertise.saved = false;
            return;
        }
        self.advertise.error = None;
        self.write_advertise(Some(vec![typed]));
    }

    /// Ask the node to apply `urls` (`None` clears back to the derived default), and adopt exactly
    /// what it reports back — never what was clicked.
    ///
    /// The same read-back discipline [`Self::save_margin`] follows, for the same money-honesty
    /// reason: a write the node clamps, refuses, or cannot reach must never leave this pane showing
    /// the request instead of the node's own answer. A failed write clears the "Saved." note and
    /// replaces [`Self::advertise_reading`] with the failure's reason — never a stale `Known` — so
    /// a press that did not land can never leave a confident address on screen.
    fn write_advertise(&mut self, urls: Option<Vec<String>>) {
        let answer = (self.advertise_seam.write)(self.config.node_url.as_deref(), urls);
        match answer {
            AdvertiseWriteReading::Applied(applied) => {
                self.advertise.saved = true;
                self.advertise.error = None;
                self.advertise_requires_restart = Some(applied.requires_restart);
                // Redraw the field from what the node now holds, so clearing to automatic empties
                // the box rather than leaving typed text sitting over a cleared override.
                self.advertise.typed = applied
                    .info
                    .operator_override
                    .as_ref()
                    .and_then(|urls| urls.first())
                    .cloned()
                    .unwrap_or_default();
                self.advertise_reading = AdvertiseReading::Known(applied.info);
            }
            AdvertiseWriteReading::Unknown(why) => {
                self.advertise.saved = false;
                self.advertise_requires_restart = None;
                self.advertise_reading = AdvertiseReading::Unknown(why);
            }
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

    /// Set the collateral safety margin on the NODE, and adopt whatever the node says afterwards.
    ///
    /// The adopted reading is the one the node answered with, so a write that was clamped — or that
    /// did not land at all — leaves the chooser and the cost beside it showing what the node holds,
    /// never what was clicked. On a money surface that distinction is the whole point, and it is the
    /// same discipline this function applied when the value still lived in a file.
    ///
    /// A failed write clears the "Saved." note and leaves the reading `Unknown`, which the chooser
    /// draws as an unread margin rather than as a confident figure.
    fn save_margin(&mut self, margin_bp: u64) {
        let answer = (self.collateral.write_margin)(self.config.node_url.as_deref(), margin_bp);
        self.margin.saved = matches!(answer, MarginReading::Known(_));
        self.margin_reading = answer;
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
    /// A requirement reading that answered `per_store` base units, for the cost fixtures.
    ///
    /// The other fields are the shipped preview's, and none of them reaches a cost: the
    /// margin is applied to `required_per_store_dig_base_units` alone. Kept realistic rather
    /// than zeroed so a fixture is never mistaken for a census that answered nothing.
    fn requirement(per_store: u64) -> RequirementReading {
        use crate::collateral::node;
        RequirementReading::Known(node::EpochRequirement {
            epoch: 7,
            protocol_version: 1,
            required_per_store_dig_base_units: per_store,
            stores: 40,
            owners: 1_000,
            multiplier_micros: 1_000_000,
            handicap_dig_base_units: 0,
        })
    }

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

    /// **No cost state paints a numeral the pane was not told.**
    ///
    /// The fixture is the trap: the store list ANSWERS with two real stores in every case, so the
    /// only missing fact is the requirement. An implementation that defaulted an absent requirement
    /// to zero would render a perfectly well-formed `0 $DIG` here, which reads as *this margin is
    /// free* — a confident wrong number about locked money. Each unknown must therefore carry a
    /// SENTENCE, and the assertion is on the `Value` variant rather than on the text, because a
    /// `Value::Measure` of `"0"` and a `Value::Unknown` are what the renderer draws differently.
    #[test]
    fn no_cost_state_paints_a_zero_when_the_requirement_is_unknown() {
        use crate::collateral::node::CollateralUnknown;
        use crate::collateral::{cost, CostReading, CostUnknown, SafetyMargin};

        let held = funding_fixture(CollateralFundingState::Funded);
        let margin = SafetyMargin::default();

        for reading in [
            cost(
                margin,
                &RequirementReading::Unknown(CollateralUnknown::NotCensused),
                &held,
            ),
            cost(margin, &requirement(1_036), &BufferReading::Pending),
            cost(
                margin,
                &requirement(1_036),
                &BufferReading::Unknown(BufferUnknown::ReadFailed(CollateralUnknown::NoNode)),
            ),
        ] {
            let items = cost_readouts(&reading);
            assert_eq!(items.len(), 1, "an unknown cost is one line, not a table");
            match &items[0].value {
                Value::Unknown(why) => assert!(
                    !why.is_empty(),
                    "an unknown must say WHY, or it is a dead end"
                ),
                other => panic!("{reading:?} rendered as {other:?} instead of an unknown"),
            }
        }

        // The control: with BOTH facts in hand the same function does produce figures, or the
        // assertions above would pass against a version that could never show a cost at all.
        let known = cost(margin, &requirement(1_036), &held);
        assert!(matches!(known, CostReading::Known(_)));
        let items = cost_readouts(&known);
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0].value,
            Value::Measure {
                amount: "0.253".to_string(),
                unit: "$DIG".to_string(),
            },
            "the extra is 11 DIG base units over each of the node's 23 served pairs"
        );
        assert_eq!(
            items[1].value,
            Value::Measure {
                amount: "24.081".to_string(),
                unit: "$DIG".to_string(),
            }
        );

        // And the reasons are distinct, so a person is told which thing is missing rather than a
        // single "unavailable" that names no remedy.
        let no_requirement = cost_readouts(&CostReading::Unknown(CostUnknown::NoRequirement));
        let no_pairs = cost_readouts(&CostReading::Unknown(CostUnknown::PairsUnknown(
            BufferUnknown::ReadFailed(CollateralUnknown::NoNode),
        )));
        assert_ne!(no_requirement[0].value, no_pairs[0].value);
    }

    /// **Two different reasons produce two different SENTENCES on the pane** — the acceptance bar
    /// for dig-app#325, and the one thing a test asserting "a sentence is shown" cannot see.
    ///
    /// Pairwise over every reason the pane can reach, not a sampled pair: a fold into a neighbour's
    /// arm shows up only when the two folded reasons are the two compared. Every fixture varies
    /// exactly one thing — the reason — so a difference here came from the reason and nothing else.
    ///
    /// The named fallback is included in the same set. It must be distinct from all twelve too,
    /// because its sentence promises the margin is saved and applied, and borrowing that promise
    /// for a reason that has its own remedy is the reverse of this defect.
    #[test]
    fn two_different_unknown_reasons_read_as_two_different_sentences() {
        use crate::collateral::node::CollateralUnknown;
        use crate::collateral::{CostReading, CostUnknown};

        let mut states = vec![CostUnknown::NoRequirement];
        states.extend(
            CollateralUnknown::all()
                .into_iter()
                .map(CostUnknown::RequirementUnknown),
        );
        states.extend(
            CollateralUnknown::all()
                .into_iter()
                .map(|reason| CostUnknown::PairsUnknown(BufferUnknown::ReadFailed(reason))),
        );
        states.extend(
            CollateralBufferUnknownReason::ALL
                .iter()
                .map(|&reason| CostUnknown::PairsUnknown(BufferUnknown::NodeCannotSay(reason))),
        );

        let sentences: Vec<(String, String)> = states
            .iter()
            .map(|why| {
                let items = cost_readouts(&CostReading::Unknown(why.clone()));
                assert_eq!(items.len(), 1, "an unknown cost is one line, not a table");
                let Value::Unknown(sentence) = &items[0].value else {
                    panic!("{why:?} rendered a figure it was never given");
                };
                assert!(!sentence.is_empty(), "{why:?} named no remedy at all");
                (format!("{why:?}"), sentence.clone())
            })
            .collect();

        // The `ReadFailed` and `RequirementUnknown` families deliberately SHARE their sentences —
        // a control call fails identically whichever collateral verb it names, and that text is
        // written once. So distinctness is asserted WITHIN each family, which is where a collapse
        // would happen, rather than across families, where sharing is the intended design.
        let requirement_family = &sentences[1..1 + CollateralUnknown::all().len()];
        let buffer_family =
            &sentences[sentences.len() - CollateralBufferUnknownReason::ALL.len()..];
        for family in [requirement_family, buffer_family] {
            for (i, (left_name, left)) in family.iter().enumerate() {
                for (right_name, right) in &family[i + 1..] {
                    assert_ne!(
                        left, right,
                        "{left_name} and {right_name} read as the same sentence"
                    );
                }
            }
        }

        // The generic fallback is not any reason's sentence. It says the choice is saved and
        // applied, which is a promise none of the reasons above is entitled to make.
        let generic = &sentences[0].1;
        for (name, sentence) in &sentences[1..] {
            assert_ne!(generic, sentence, "{name} borrowed the generic sentence");
        }
    }

    /// The Settings pane drawn through `seam`, as the glyphs it actually paints.
    ///
    /// The hosted-store list is deliberately ONE entry while the funding fixtures report 23 served
    /// pairs. That gap is the whole point: it is the second actor that lets a drawn total tell the
    /// node's pair count apart from a store-list length, which no fixture holding one count can do.
    fn painted(seam: CollateralSeam) -> String {
        let view = TrayView {
            running: true,
            hosted_stores: crate::hosted_stores::HostedStoresReading::Known(vec![
                crate::hosted_stores::HostedStore {
                    store_id: "store-0".to_string(),
                    pinned: false,
                    capsule_count: 1,
                    total_bytes: 1,
                },
            ]),
            ..TrayView::default()
        };
        let session = Session::from_store_through(
            Some(std::sync::Arc::new(FakeStore::holding(
                AgentConfig::default(),
            ))),
            seam,
            no_node_advertise_seam(),
        );
        painted_pane(&view, session, super::super::super::shell::SHELL_MIN).join(" | ")
    }

    /// [`painted`]'s mirror for the advertise card: the collateral seam is held fixed at
    /// [`no_node_collateral_seam`] while `seam` varies, so a picture of the advertise card is never
    /// mistaken for a picture of the margin or funding cards changing too.
    fn painted_with_advertise(seam: AdvertiseSeam) -> String {
        let view = TrayView::default();
        let session = Session::from_store_through(
            Some(std::sync::Arc::new(FakeStore::holding(
                AgentConfig::default(),
            ))),
            no_node_collateral_seam(),
            seam,
        );
        painted_pane(&view, session, super::super::super::shell::SHELL_MIN).join(" | ")
    }

    /// **The funding card reaches the drawn pane, in every state.**
    ///
    /// `funding_readouts` returning rows proves only that a function returns rows. This paints the
    /// real pane and reads the glyphs back, which is the difference between a reader that works and
    /// a reader nothing calls — the defect this ticket exists to fix, where `read_buffer` was correct
    /// and had no consumer anywhere in the binary.
    ///
    /// The unread case is asserted as a NEGATIVE on the figures as well as a positive on the reason:
    /// a card that drew its recommendation from a default would still print a number here.
    #[test]
    fn the_funding_card_is_drawn_into_the_pane() {
        use crate::collateral::node::CollateralUnknown;

        let short = painted(funding_seam(|_| {
            funding_fixture(CollateralFundingState::ShortNow)
        }));
        assert!(short.contains(copy::settings::FUNDING_CARD), "{short}");
        assert!(
            short.contains(funding_label(CollateralFundingState::ShortNow)),
            "the verdict must be named: {short}"
        );
        // 148_000 recommended less 40_000 held. The figure, not just the row.
        assert!(
            short.contains(&crate::amount::format_dig(108_000)),
            "the amount to add must be drawn: {short}"
        );
        // The working, from the payload: the node's 23 served pairs and its 3-epoch horizon.
        assert!(
            short.contains("23"),
            "the pairs served must be drawn: {short}"
        );
        assert!(
            short.contains("3 epochs"),
            "the node's horizon must be drawn: {short}"
        );

        let funded = painted(funding_seam(|_| {
            funding_fixture(CollateralFundingState::Funded)
        }));
        assert!(
            funded.contains(funding_label(CollateralFundingState::Funded)),
            "{funded}"
        );
        assert!(
            !funded.contains(copy::settings::FUNDING_ADD),
            "a funded node is not asked to add anything: {funded}"
        );

        let unread = painted(funding_seam(|_| {
            BufferReading::Unknown(BufferUnknown::ReadFailed(CollateralUnknown::NodeCannotRead))
        }));
        assert!(unread.contains(copy::settings::FUNDING_CARD), "{unread}");
        assert!(
            !unread.contains(&crate::amount::format_dig(148_000)),
            "no recommendation may be drawn when none was read: {unread}"
        );
        assert!(
            !unread.contains(copy::settings::FUNDING_ADD),
            "nothing can be asked for when nothing was read: {unread}"
        );
    }

    /// **Every funding state is visible, and no unread state shows a figure.**
    ///
    /// The five states a person can be in are the four the node names plus the one where nothing was
    /// read, and each must be reachable — a card that renders only the funded case is the dead
    /// control this ticket exists to remove.
    ///
    /// The load-bearing halves are the negatives. `Value::is_known()` is false for exactly one
    /// variant, so asserting it on the three no-answer readings pins that a pending read, a node
    /// that cannot say, and a failed read all produce an ABSENCE rather than a zero — which is what
    /// a version that defaulted the buffer to `0` would show, and which reads as "you need no more
    /// $DIG" on a node that may be uncollateralised. The known cases are the control: without them
    /// the same assertions would pass against a card that could never show a figure at all.
    #[test]
    fn every_funding_state_is_drawn_and_no_unread_one_carries_a_figure() {
        use crate::collateral::node::{CollateralBufferUnknownReason, CollateralUnknown};

        for state in CollateralFundingState::ALL {
            let rows = funding_readouts(&funding_fixture(*state));
            assert!(
                rows.iter().all(|row| row.value.is_known()),
                "{state:?} answered, so every row it draws is a real reading: {rows:?}"
            );
            assert_eq!(
                rows[0].value,
                Value::Word(funding_label(*state).to_string()),
                "{state:?} must be named by its own words"
            );
            // The working, from the payload and not from any constant here: the pair count, the
            // per-store requirement, the margin, and the horizon.
            let drawn: Vec<&String> = rows.iter().map(|row| &row.label).collect();
            for label in [
                copy::settings::FUNDING_RECOMMENDED,
                copy::settings::FUNDING_SPENDABLE,
                copy::settings::FUNDING_PAIRS,
                copy::settings::FUNDING_REQUIRED,
                copy::settings::FUNDING_MARGIN,
                copy::settings::FUNDING_HORIZON,
            ] {
                assert!(
                    drawn.iter().any(|held| held.as_str() == label),
                    "{state:?} must show its working: {label} is missing from {drawn:?}"
                );
            }
            assert!(
                funding_sentence(&funding_fixture(*state)).is_some(),
                "{state:?} must explain itself in a sentence"
            );
        }

        // The three no-answer readings: one reason each, no figure, and no sentence duplicating it.
        let unread = [
            BufferReading::Pending,
            BufferReading::Unknown(BufferUnknown::NodeCannotSay(
                CollateralBufferUnknownReason::ReclaimStateUnknown,
            )),
            BufferReading::Unknown(BufferUnknown::ReadFailed(CollateralUnknown::NodeCannotRead)),
        ];
        let mut reasons = Vec::new();
        for reading in &unread {
            let rows = funding_readouts(reading);
            assert_eq!(
                rows.len(),
                1,
                "an unknown is one line, not a table: {rows:?}"
            );
            let Value::Unknown(why) = &rows[0].value else {
                panic!("{reading:?} drew {:?} instead of an absence", rows[0].value);
            };
            assert!(
                !why.is_empty(),
                "an unknown must say WHY, or it is a dead end"
            );
            assert!(
                funding_sentence(reading).is_none(),
                "{reading:?} has already said its piece; a second sentence reads as a second fact"
            );
            reasons.push(why.clone());
        }
        // Distinct reasons, because the remedies differ: a wait, the node's own bookkeeping, and the
        // call itself. Collapsing them would answer a reclaim-state gap with "check your connection".
        reasons.sort();
        let before = reasons.len();
        reasons.dedup();
        assert_eq!(before, reasons.len(), "each unknown names its OWN remedy");
    }

    /// **Whether the operator is asked for $DIG follows the NODE's verdict, not this app's
    /// subtraction.**
    ///
    /// The two axes move independently in the contract's own KAT, so the fixtures here make them
    /// DISAGREE on purpose — which is the only way to tell the two implementations apart. A version
    /// gated on `recommended > spendable` agrees with this one on every fixture where the balance
    /// tracks the state, which is exactly what the previous version of this test used, and why it
    /// could not have caught the defect:
    ///
    /// * **`Funded` with a balance below the recommendation** — the arithmetic says "ask", the node
    ///   says the operator is fine. Asking here invents a shortfall the node did not report.
    /// * **`ShortNow` with a balance at the recommendation** — the arithmetic says "silent", the node
    ///   says the stores are uncollateralised. Staying silent here withholds the one row a person in
    ///   that state most needs.
    ///
    /// The control pair below keeps the ordinary, agreeing cases asserted too, so an implementation
    /// that simply inverted the rule fails as well.
    #[test]
    fn the_add_row_follows_the_nodes_verdict_and_not_a_local_comparison() {
        fn add_row(state: CollateralFundingState, spendable: u64) -> Option<Readout> {
            let BufferReading::Known(mut buffer) = funding_fixture(state) else {
                panic!("the fixture answered");
            };
            buffer.spendable_dig_base_units = spendable;
            funding_readouts(&BufferReading::Known(buffer))
                .into_iter()
                .find(|row| row.label == copy::settings::FUNDING_ADD)
        }

        // The two axes disagreeing. `funding_fixture` recommends 148_000 in every state.
        assert!(
            add_row(CollateralFundingState::Funded, 1_000).is_none(),
            "a node that says Funded must not be asked for $DIG, whatever the balance arithmetic says"
        );
        assert!(
            add_row(CollateralFundingState::ShortNow, 148_000).is_some(),
            "a node that says ShortNow must still name a row, even where the gap computes to zero"
        );

        // The ordinary, agreeing cases, so an inverted rule fails too.
        assert!(add_row(CollateralFundingState::Funded, 190_000).is_none());
        assert_eq!(
            add_row(CollateralFundingState::ShortNow, 40_000).map(|row| row.value),
            Some(Value::Measure {
                amount: crate::amount::format_dig(108_000),
                unit: "$DIG".to_string(),
            }),
            "148_000 recommended less the 40_000 held, as the figure and not merely as some measure"
        );

        // The state the rule is easiest to get wrong: covered every epoch, short of the cushion. It
        // is NOT a shortfall state, so "ask on the shortfall states" would wrongly stay silent, and a
        // person cannot close a gap nobody showed them.
        assert!(
            add_row(CollateralFundingState::BelowRecommendedBuffer, 132_000).is_some(),
            "a node below its recommended buffer must still be shown the gap"
        );
    }

    /// **The card's own sentences overstate nothing either.**
    ///
    /// The same sweep `runway::tests::no_body_claims_more_than_the_node_reported` runs over the
    /// notification bodies, applied to the sentences the CARD draws — which are different strings
    /// and were, until the round-3 gate, the ones carrying the unhedged claim. A guard on one
    /// surface does not cover the other.
    #[test]
    fn no_card_sentence_claims_more_than_the_node_reported() {
        let forbidden = [
            "offline",
            "unavailable",
            "inaccessible",
            "earn nothing",
            "earns nothing",
            "cannot find them",
            "will be skipped",
        ];
        for state in CollateralFundingState::ALL {
            let spoken = funding_sentence(&funding_fixture(*state))
                .expect("a known state explains itself")
                .to_lowercase();
            for word in forbidden {
                assert!(
                    !spoken.contains(word),
                    "{state:?} says {word:?}, which is more than the node reported: {spoken}"
                );
            }
        }
    }

    /// **The horizon drawn is the node's, not a constant in this app.**
    ///
    /// The same buffer over a different horizon is a different claim, so a card that supplied its
    /// own number would be making a claim the node never made. Two different horizons on otherwise
    /// identical answers, because a single one is satisfied by any hard-coded value that happens to
    /// match the fixture.
    #[test]
    fn the_horizon_shown_comes_from_the_payload() {
        let BufferReading::Known(mut buffer) = funding_fixture(CollateralFundingState::Funded)
        else {
            panic!("the fixture answered");
        };
        assert_eq!(buffer.horizon_epochs, 3);
        let three = funding_readouts(&BufferReading::Known(buffer));

        buffer.horizon_epochs = 9;
        let nine = funding_readouts(&BufferReading::Known(buffer));

        let horizon = |rows: &[Readout]| {
            rows.iter()
                .find(|row| row.label == copy::settings::FUNDING_HORIZON)
                .map(|row| row.value.clone())
                .expect("the horizon is drawn")
        };
        assert_eq!(horizon(&three), Value::Word("3 epochs".to_string()));
        assert_eq!(horizon(&nine), Value::Word("9 epochs".to_string()));
    }

    /// **The total rests on the pair count the NODE reported, never on the length of dig-app's
    /// hosted-store list.**
    ///
    /// This is the test the fix exists for, and it is here rather than in `collateral` because this
    /// is the only place both counts exist at once: `cost` no longer sees a store list, so from
    /// inside that module the old and new implementations agree on every expressible input.
    ///
    /// The two counts are deliberately DIFFERENT — a 4-entry store list beside a node serving 23
    /// pairs — and they are different in the direction the defect fails in: dig-app's list is keyed
    /// on `store_id`, so a store serving several owners is one entry and several postings, and
    /// counting entries yields a total no larger than the truth. An implementation that went back to
    /// the list length would total `1_047 * 4` here rather than `1_047 * 23`, which is the smaller
    /// figure — and understating money to be locked is the direction that costs an operator an
    /// epoch. Asserting the LARGER number is what makes the failure direction, and not merely an
    /// inequality, the thing pinned.
    #[test]
    fn a_total_rests_on_the_nodes_pair_count_not_the_store_list() {
        use crate::collateral::{cost, CostReading, SafetyMargin};
        use crate::hosted_stores::{HostedStore, HostedStoresReading};

        let store_list = HostedStoresReading::Known(
            (0..4)
                .map(|i| HostedStore {
                    store_id: format!("store-{i}"),
                    pinned: false,
                    capsule_count: 1,
                    total_bytes: 1,
                })
                .collect(),
        );
        let HostedStoresReading::Known(entries) = &store_list else {
            panic!("the fixture answered");
        };
        assert_eq!(entries.len(), 4, "the wrong count, kept in view on purpose");

        let CostReading::Known(held) = cost(
            SafetyMargin::default(),
            &requirement(1_036),
            &funding_fixture(CollateralFundingState::Funded),
        ) else {
            panic!("both facts are known here");
        };
        assert_eq!(held.pairs_served, 23, "the node's own served-pair count");
        assert_eq!(held.total_posted_dig_base_units, 1_047 * 23);
        assert!(
            held.total_posted_dig_base_units > 1_047 * entries.len() as u64,
            "counting store-list entries would UNDERSTATE the total, which is the direction \
             this fix exists to prevent"
        );
    }

    /// **Choosing a preset writes it to the NODE, and the pane then shows what the NODE returned.**
    ///
    /// The property #301 held against a config file, kept intact across the move to the control
    /// plane (dig-app#302). Run three ways on purpose, because each one fails differently:
    ///
    /// * an honest node applies the choice and the pane reflects it;
    /// * a node that CLAMPS the request to a different value — the case the contract exists for,
    ///   since `.set` returns the margin now in force rather than an echo — must leave the pane
    ///   showing what the node applied, not what was clicked;
    /// * a node that cannot be reached must leave the pane with no margin at all and NOT say
    ///   "Saved.".
    ///
    /// The clamping case is the load-bearing one. An implementation that stored the requested
    /// `margin_bp` locally and never looked at the answer passes the first and third — the first
    /// because the values happen to agree, the third because there is nothing to show — and is
    /// exactly the two-writer drift this ticket removes.
    #[test]
    fn choosing_a_margin_shows_what_the_node_applied_not_what_was_clicked() {
        use crate::collateral::node::CollateralUnknown;
        use crate::collateral::{SafetyMargin, SAFETY_MARGIN_BP_GENEROUS, SAFETY_MARGIN_BP_TIGHT};

        fn session_with(write: fn(Option<&str>, u64) -> MarginReading) -> Session {
            Session::from_store_through(
                Some(std::sync::Arc::new(FakeStore::holding(
                    AgentConfig::default(),
                ))),
                CollateralSeam {
                    // A node with nothing to say yet, so the starting state is honestly unread and
                    // any margin the pane ends up showing came from the WRITE.
                    read_margin: |_| MarginReading::Unknown(CollateralUnknown::NodeCannotRead),
                    read_requirement: |_| {
                        RequirementReading::Unknown(CollateralUnknown::NodeCannotRead)
                    },
                    read_buffer: |_| {
                        BufferReading::Unknown(BufferUnknown::ReadFailed(
                            CollateralUnknown::NodeCannotRead,
                        ))
                    },
                    write_margin: write,
                },
                no_node_advertise_seam(),
            )
        }

        let mut honest =
            session_with(|_, bp| MarginReading::Known(SafetyMargin::of_basis_points(bp)));
        honest.act_locally(Local::SetMargin(SAFETY_MARGIN_BP_GENEROUS));
        assert_eq!(
            honest.margin_reading.margin().map(|m| m.margin_bp),
            Some(SAFETY_MARGIN_BP_GENEROUS)
        );
        assert!(honest.margin.saved);

        // The node applies something OTHER than the request.
        let mut clamping = session_with(|_, _| {
            MarginReading::Known(SafetyMargin::of_basis_points(SAFETY_MARGIN_BP_TIGHT))
        });
        clamping.act_locally(Local::SetMargin(SAFETY_MARGIN_BP_GENEROUS));
        assert_eq!(
            clamping.margin_reading.margin().map(|m| m.margin_bp),
            Some(SAFETY_MARGIN_BP_TIGHT),
            "the pane must show the margin the node applied, never the one that was clicked"
        );

        // Nobody answered.
        let mut unreachable =
            session_with(|_, _| MarginReading::Unknown(CollateralUnknown::NoNode));
        unreachable.act_locally(Local::SetMargin(SAFETY_MARGIN_BP_GENEROUS));
        assert_eq!(
            unreachable.margin_reading.margin(),
            None,
            "a write that reached nobody must leave no figure on screen"
        );
        assert!(
            !unreachable.margin.saved,
            "a write that did not land must not be confirmed as saved"
        );
    }

    /// **The margin card DRAWS each of the three collateral states as itself.**
    ///
    /// Stands in for a committed screenshot of each state, and is stronger than one for the property
    /// that matters here: it asserts the painted STRINGS, so a card that renders a figure it was not
    /// given fails, where a picture would need somebody to notice.
    ///
    /// The three cases are the ones a person can actually be in, and each is checked for what it
    /// must say AND for what it must not:
    ///
    /// * **priced** — real figures, and the chooser showing the node's percentage;
    /// * **margin, no requirement** — the ordinary state of every node until the server side ships.
    ///   It must still promise the choice is saved and applied, because the node holds it;
    /// * **unread** — no percentage anywhere, and it must NOT carry that promise, which would be
    ///   false when nothing has been read.
    #[test]
    fn the_margin_card_draws_each_collateral_state_as_itself() {
        use crate::collateral::node::{CollateralUnknown, EpochRequirement};
        use crate::collateral::SafetyMargin;

        /// A mature-network epoch whose per-store requirement is a round 5_000 base units, so the
        /// +1% margin's extra is an exact 50 and an off-by-one in the arithmetic is visible.
        fn priced_epoch() -> RequirementReading {
            RequirementReading::Known(EpochRequirement {
                epoch: 7,
                protocol_version: 1,
                required_per_store_dig_base_units: 5_000,
                stores: 40,
                owners: 1_000,
                multiplier_micros: 1_000_000,
                handicap_dig_base_units: 0,
            })
        }

        // 1. Both served.
        let priced = painted(CollateralSeam {
            read_margin: |_| MarginReading::Known(SafetyMargin::default()),
            read_requirement: |_| priced_epoch(),
            read_buffer: |_| funding_fixture(CollateralFundingState::Funded),
            write_margin: |_, bp| MarginReading::Known(SafetyMargin::of_basis_points(bp)),
        });
        assert!(priced.contains(copy::settings::MARGIN_CARD), "{priced}");
        assert!(
            priced.contains(copy::settings::MARGIN_EFFECTIVE),
            "the extra locked must be named: {priced}"
        );
        // 5_000 base units per store with +1% posts 5_050, so each served pair locks 50 extra —
        // across the 23 pairs the node reported, 1_150. The multiplication is deliberately visible:
        // an implementation that counted this session's store list instead would print a different,
        // smaller figure here.
        assert!(
            priced.contains(&crate::amount::format_dig(50 * 23)),
            "the card must show the extra $DIG this margin locks: {priced}"
        );
        // The load-bearing negative, and the reason `painted` seeds a ONE-entry hosted-store list
        // beside a node reporting 23 served pairs: an implementation that totalled the store list
        // would draw 50 here. That is the SMALLER figure, and understating money to be locked is the
        // direction that costs an operator an epoch — so this pins the failure direction, not merely
        // that two numbers differ.
        assert!(
            !priced.contains(&crate::amount::format_dig(50)),
            "the total must not be drawn from dig-app's store list, which under-counts: {priced}"
        );
        assert!(
            !priced.contains(copy::settings::MARGIN_NOT_READ),
            "a priced card must not claim the margin is unread: {priced}"
        );

        // 2. The margin is known, the price is not.
        let unpriced = painted(CollateralSeam {
            read_margin: |_| MarginReading::Known(SafetyMargin::default()),
            read_requirement: |_| RequirementReading::Unknown(CollateralUnknown::NotCensused),
            read_buffer: |_| funding_fixture(CollateralFundingState::Funded),
            write_margin: |_, bp| MarginReading::Known(SafetyMargin::of_basis_points(bp)),
        });
        assert!(
            unpriced.contains(CollateralUnknown::NotCensused.remedy()),
            "the reason's OWN remedy must reach the glyphs, not a generic stand-in: {unpriced}"
        );
        assert!(
            !unpriced.contains(copy::settings::MARGIN_NOT_READ),
            "the MARGIN was read here; only its price was not: {unpriced}"
        );
        assert!(
            !unpriced.contains(&crate::amount::format_dig(50 * 23)),
            "no cost may be drawn from a requirement nobody reported: {unpriced}"
        );

        // 2b. The SAME card, the SAME margin, the SAME buffer — one different reason.
        //
        // This is the acceptance bar for dig-app#325, asserted on the glyphs a person actually
        // reads rather than on an intermediate type. The two reasons pull in opposite directions:
        // an uncensused node clears on its own, and a node that cannot read its own balance needs
        // its wallet looked at. Only the reason varies between the two fixtures, so a difference
        // here cannot have come from anything else — and a version that collapsed both into one
        // sentence, which is what shipped before, fails on the `assert_ne` below rather than
        // passing every "a sentence is shown" check as it did.
        let balance_unreadable = painted(CollateralSeam {
            read_margin: |_| MarginReading::Known(SafetyMargin::default()),
            read_requirement: |_| RequirementReading::Unknown(CollateralUnknown::BalanceUnreadable),
            read_buffer: |_| funding_fixture(CollateralFundingState::Funded),
            write_margin: |_, bp| MarginReading::Known(SafetyMargin::of_basis_points(bp)),
        });
        assert!(
            balance_unreadable.contains(CollateralUnknown::BalanceUnreadable.remedy()),
            "the balance-unreadable remedy must reach the glyphs: {balance_unreadable}"
        );
        assert_ne!(
            unpriced, balance_unreadable,
            "two different unknown reasons painted the same card"
        );
        assert!(
            !balance_unreadable.contains(CollateralUnknown::NotCensused.remedy()),
            "the balance reason must not borrow the census reason's words"
        );

        // 3. Neither served — every node in the world, today.
        let unread = painted(CollateralSeam {
            read_margin: |_| MarginReading::Unknown(CollateralUnknown::NodeCannotRead),
            read_requirement: |_| RequirementReading::Unknown(CollateralUnknown::NodeCannotRead),
            read_buffer: |_| {
                BufferReading::Unknown(BufferUnknown::ReadFailed(CollateralUnknown::NodeCannotRead))
            },
            write_margin: |_, _| MarginReading::Unknown(CollateralUnknown::NodeCannotRead),
        });
        assert!(
            unread.contains(copy::settings::MARGIN_NOT_READ),
            "an unread margin must say so: {unread}"
        );
        assert!(
            !unread.contains(copy::settings::MARGIN_NO_REQUIREMENT),
            "it must NOT promise the choice is saved when nothing was read: {unread}"
        );
        assert!(
            unread.contains(copy::settings::MARGIN_UNREAD),
            "the chooser must show the unread word: {unread}"
        );
        // The load-bearing negative: the shipped default is +1%, and a card that fell back to it
        // would print "1%" here while the node's margin is entirely unknown. The priced case above
        // is the control that proves "1%" IS drawn when a margin was actually read.
        assert!(
            priced.contains("1%"),
            "control: a read margin is drawn as its percentage: {priced}"
        );
        assert!(
            !unread.contains("1%"),
            "an unread margin must not be drawn as the shipped default: {unread}"
        );
    }

    /// **dig-app keeps NO local copy of the margin.**
    ///
    /// The substance of dig-app#302, asserted structurally rather than behaviourally: the settings
    /// file round-trips through `AgentConfig`, so if a margin field still existed it would serialise
    /// here. A behavioural test could be satisfied by a copy that merely happens not to be read.
    /// **The funding card names no address, so it cannot name the wrong one (dig-app#341).**
    ///
    /// This card is the only other place in the app that talks about funding, and the acceptance
    /// criterion is that no funding surface can be completed against the USER's address. It meets
    /// that by carrying no destination at all: its figures come from `control.collateral.buffer`,
    /// which is the node reporting on its OWN spendable $DIG, and there is nothing here to press.
    ///
    /// Asserted rather than assumed because the property is one a future edit could quietly break —
    /// adding a "send $DIG here" line to this card, sourced from `facts.receive_address`, is a
    /// three-line change that would look like an improvement. The fixture gives the pane a funded,
    /// unlocked account precisely so that a user address IS available to leak; a locked fixture
    /// would pass this test by having nothing to print.
    #[test]
    fn the_funding_card_names_no_address_and_so_cannot_name_the_wrong_one() {
        const USER_ADDRESS: &str = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";
        let view = TrayView {
            running: true,
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            receive_address: Some(USER_ADDRESS.to_string()),
            ..TrayView::default()
        };
        let said = painted_pane(&view, Session::from_store(None), 900.0);

        assert!(
            said.iter().any(|word| word == copy::settings::FUNDING_CARD),
            "the funding card is not on the Settings tab at all: {said:?}"
        );
        assert!(
            !said.iter().any(|word| word.contains(USER_ADDRESS)),
            "the funding card printed the USER wallet's address: {said:?}"
        );
        // No address of ANY kind, which is the stronger property and the one that survives a
        // rewording: an address this card printed would be a destination whether or not it happened
        // to be the user's on the day the test ran.
        assert!(
            !said.iter().any(|word| word.contains("xch1")),
            "the funding card printed an address, which is a destination: {said:?}"
        );
    }

    #[test]
    fn the_settings_file_carries_no_margin_of_its_own() {
        let written = serde_json::to_string(&AgentConfig::default()).expect("config serialises");
        assert!(
            !written.contains("collateral"),
            "the margin must live only in the node; agent.json wrote {written}"
        );
        assert!(
            !written.contains("margin_bp"),
            "and not under another name either: {written}"
        );
    }

    // -- dig-app#387: the mirror advertise-URL card ---------------------------------------------

    /// A session whose advertise seam is `write`, over an otherwise-fixed no-node fixture.
    fn advertise_session_with(
        write: fn(Option<&str>, Option<Vec<String>>) -> AdvertiseWriteReading,
    ) -> Session {
        Session::from_store_through(
            Some(std::sync::Arc::new(FakeStore::holding(
                AgentConfig::default(),
            ))),
            no_node_collateral_seam(),
            AdvertiseSeam {
                read: |_| AdvertiseReading::Unknown(AdvertiseUnknown::NoNode),
                write,
            },
        )
    }

    /// **A write is read back from what the node applied, never from what was clicked** —
    /// [`crate::collateral`]'s `choosing_a_margin_shows_what_the_node_applied_not_what_was_clicked`,
    /// restated for the advertise override. Three cases: the node agrees, the node applies
    /// something ELSE (this contract has no clamp, but a future one might, and the read-back
    /// discipline must not assume otherwise), and nobody answers.
    #[test]
    fn choosing_an_advertise_override_shows_what_the_node_applied_not_what_was_clicked() {
        fn applied(urls: &[&str]) -> AdvertiseWriteReading {
            AdvertiseWriteReading::Applied(crate::mirror_advertise::AdvertiseApplied {
                info: crate::mirror_advertise::AdvertiseInfo {
                    urls: urls.iter().map(|u| u.to_string()).collect(),
                    operator_override: Some(urls.iter().map(|u| u.to_string()).collect()),
                    state: MirrorAdvertiseState::AdvertisingOverride,
                },
                requires_restart: true,
            })
        }

        let mut honest = advertise_session_with(|_, _| applied(&["dig://203.0.113.7:9776"]));
        honest.advertise.typed = "dig://203.0.113.7:9776".to_string();
        honest.act_locally(Local::SaveAdvertise);
        assert_eq!(
            honest.advertise_reading,
            AdvertiseReading::Known(crate::mirror_advertise::AdvertiseInfo {
                urls: vec!["dig://203.0.113.7:9776".to_string()],
                operator_override: Some(vec!["dig://203.0.113.7:9776".to_string()]),
                state: MirrorAdvertiseState::AdvertisingOverride,
            })
        );
        assert!(honest.advertise.saved);

        // The node applies something OTHER than the request.
        let mut differs = advertise_session_with(|_, _| applied(&["dig://198.51.100.9:9776"]));
        differs.advertise.typed = "dig://203.0.113.7:9776".to_string();
        differs.act_locally(Local::SaveAdvertise);
        assert_eq!(
            differs.advertise_reading.info().map(|i| i.urls.clone()),
            Some(vec!["dig://198.51.100.9:9776".to_string()]),
            "the pane must show what the node applied, never what was typed"
        );

        // Nobody answered.
        let mut unreachable =
            advertise_session_with(|_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode));
        unreachable.advertise.typed = "dig://203.0.113.7:9776".to_string();
        unreachable.act_locally(Local::SaveAdvertise);
        assert_eq!(
            unreachable.advertise_reading.info(),
            None,
            "a write that reached nobody must leave no address on screen"
        );
        assert!(
            !unreachable.advertise.saved,
            "a write that did not land must not be confirmed as saved"
        );
    }

    /// **A save the node reports still needs a restart is never rendered as "saved and live".**
    ///
    /// This is the exact money-honesty defect the contract's own `requires_restart` field exists to
    /// prevent (`SetMirrorAdvertiseUrlsResult::requires_restart`'s own doc): a person told their
    /// address is live when the node has not applied it yet would stop looking for the real
    /// remedy — restarting the node.
    #[test]
    fn a_write_needing_a_restart_is_never_shown_as_already_live() {
        fn applied(requires_restart: bool) -> AdvertiseWriteReading {
            AdvertiseWriteReading::Applied(crate::mirror_advertise::AdvertiseApplied {
                info: crate::mirror_advertise::AdvertiseInfo {
                    urls: vec!["dig://203.0.113.7:9776".to_string()],
                    operator_override: Some(vec!["dig://203.0.113.7:9776".to_string()]),
                    state: MirrorAdvertiseState::AdvertisingOverride,
                },
                requires_restart,
            })
        }

        let mut needs_restart = advertise_session_with(|_, _| applied(true));
        needs_restart.advertise.typed = "dig://203.0.113.7:9776".to_string();
        needs_restart.act_locally(Local::SaveAdvertise);
        let note = advertise_note(
            needs_restart.advertise.saved,
            needs_restart.advertise_requires_restart,
        );
        assert_eq!(note, Some(copy::settings::ADVERTISE_SAVED_NEEDS_RESTART));
        assert_ne!(note, Some(copy::settings::ADVERTISE_SAVED_LIVE));

        let mut live = advertise_session_with(|_, _| applied(false));
        live.advertise.typed = "dig://203.0.113.7:9776".to_string();
        live.act_locally(Local::SaveAdvertise);
        assert_eq!(
            advertise_note(live.advertise.saved, live.advertise_requires_restart),
            Some(copy::settings::ADVERTISE_SAVED_LIVE)
        );
    }

    /// **An unusable typed address never reaches the node.**
    ///
    /// The seam's `write` panics if called at all, so this fails loudly rather than quietly if
    /// local validation is ever bypassed — the same "refuse before it reaches the write" property
    /// `setting_card`'s own test asserts for the two file-backed fields.
    #[test]
    fn an_unusable_typed_address_never_reaches_the_node() {
        let mut session = advertise_session_with(|_, _| {
            panic!("looks_like_a_url should have refused this before any write was attempted")
        });
        for bad in ["not-a-url", "two words", "http://"] {
            session.advertise.typed = bad.to_string();
            session.act_locally(Local::SaveAdvertise);
            assert!(
                session.advertise.error.is_some(),
                "{bad:?} should have been refused with a reason"
            );
            assert!(!session.advertise.saved);
        }
    }

    /// **Emptying the field and pressing Save clears back to automatic — it does not send an empty
    /// list.**
    ///
    /// The contract refuses `Some(vec![])` as ambiguous (see [`crate::mirror_advertise`]'s module
    /// doc); this asserts dig-app never constructs that request even when a person reaches
    /// "automatic" via Save rather than via the dedicated button.
    #[test]
    fn emptying_the_field_and_saving_clears_to_automatic_never_sends_an_empty_list() {
        let mut session = advertise_session_with(|_, urls| {
            assert_eq!(
                urls, None,
                "an emptied field must clear, never send Some(vec![])"
            );
            AdvertiseWriteReading::Applied(crate::mirror_advertise::AdvertiseApplied {
                info: crate::mirror_advertise::AdvertiseInfo {
                    urls: vec!["dig://198.51.100.42:9776".to_string()],
                    operator_override: None,
                    state: MirrorAdvertiseState::AdvertisingDerived,
                },
                requires_restart: false,
            })
        });
        session.advertise.typed = "   ".to_string();
        session.act_locally(Local::SaveAdvertise);
        assert!(session.advertise.saved);
        assert_eq!(
            session.advertise.typed, "",
            "the field shows the cleared override, not blanks"
        );
    }

    /// **The advertise card draws each of dig-node#562's six states as itself, plus the two the
    /// read itself can be in.**
    ///
    /// Painted rather than asserted on the pure functions alone, for the reason
    /// `the_margin_card_draws_each_collateral_state_as_itself` is: it is the difference between a
    /// reader that works and a reader nothing calls.
    #[test]
    fn the_advertise_card_draws_each_state_as_itself() {
        let override_ = painted_with_advertise(AdvertiseSeam {
            read: |_| {
                AdvertiseReading::Known(crate::mirror_advertise::AdvertiseInfo {
                    urls: vec!["dig://203.0.113.7:9776".to_string()],
                    operator_override: Some(vec!["dig://203.0.113.7:9776".to_string()]),
                    state: MirrorAdvertiseState::AdvertisingOverride,
                })
            },
            write: |_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode),
        });
        assert!(
            override_.contains(copy::settings::ADVERTISE_CARD),
            "{override_}"
        );
        assert!(override_.contains("dig://203.0.113.7:9776"), "{override_}");
        assert!(
            override_.contains(copy::settings::ADVERTISE_STATE_OVERRIDE),
            "{override_}"
        );

        // The one state that must never read as a fault.
        let uncorroborated = painted_with_advertise(AdvertiseSeam {
            read: |_| {
                AdvertiseReading::Known(crate::mirror_advertise::AdvertiseInfo {
                    urls: vec![],
                    operator_override: None,
                    state: MirrorAdvertiseState::UncorroboratedAddress,
                })
            },
            write: |_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode),
        });
        assert!(
            uncorroborated.contains(copy::settings::ADVERTISE_STATE_UNCORROBORATED),
            "{uncorroborated}"
        );
        assert!(
            uncorroborated.contains("expected"),
            "must read as expected, not as a fault: {uncorroborated}"
        );

        let pending = painted_with_advertise(AdvertiseSeam {
            read: |_| AdvertiseReading::Pending,
            write: |_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode),
        });
        assert!(
            pending.contains(copy::settings::ADVERTISE_PENDING),
            "{pending}"
        );

        let too_old = painted_with_advertise(AdvertiseSeam {
            read: |_| AdvertiseReading::Unknown(AdvertiseUnknown::NotSupported),
            write: |_, _| AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode),
        });
        assert!(
            too_old.contains("too old"),
            "a node predating the feature must say so: {too_old}"
        );
    }

    /// **Every one of dig-node#562's six states reads as a distinct short label AND a distinct
    /// sentence.**
    ///
    /// Asserted pairwise, the same discipline `every_unknown_reason_survives_the_cost_hop_distinctly`
    /// uses: an assertion that only checked one state right passes just as happily when two OTHER
    /// states collapsed into each other.
    #[test]
    fn every_advertise_state_reads_as_itself() {
        let labels: Vec<&str> = MirrorAdvertiseState::ALL
            .iter()
            .map(|&s| advertise_state_label(s))
            .collect();
        for (i, left) in labels.iter().enumerate() {
            for right in &labels[i + 1..] {
                assert_ne!(left, right, "two states share a short label: {labels:?}");
            }
        }

        let sentences: Vec<&str> = MirrorAdvertiseState::ALL
            .iter()
            .map(|&s| {
                advertise_sentence(&AdvertiseReading::Known(
                    crate::mirror_advertise::AdvertiseInfo {
                        urls: vec![],
                        operator_override: None,
                        state: s,
                    },
                ))
                .expect("a Known reading always has a sentence")
            })
            .collect();
        for (i, left) in sentences.iter().enumerate() {
            for right in &sentences[i + 1..] {
                assert_ne!(left, right, "two states share a sentence: {sentences:?}");
            }
        }
        assert_eq!(labels.len(), 6);
        assert_eq!(sentences.len(), 6);
    }
}
