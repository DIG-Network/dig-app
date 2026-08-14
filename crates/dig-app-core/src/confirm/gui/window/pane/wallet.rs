//! The Wallet tab: where money arrives, what is held, and where it goes.
//!
//! # Why the balance leads
//!
//! A wallet exists to answer *how much do I have?*, so that answer is the first thing on the tab and
//! is set at [`crate::confirm::gui::render::size::DISPLAY`]. The two verbs follow it, and each one's
//! card is DISCLOSED by pressing it rather than drawn permanently.
//!
//! This inverts what the tab shipped with, and the header that justified the old order is worth
//! keeping as a warning. It read: *the address is the only value on the tab a person takes to
//! another device, and it is what a wallet with nothing in it needs first* — so the address and its
//! ~270 px code were the first card and the balance sat below the fold in body-sized type. Each
//! clause was true. The conclusion did not follow: a value needed for seconds a few times a month
//! had been given the space a person looks at every time they open the tab. And the sentence that
//! closed it, *"receiving is the one thing this wallet can do today"*, stopped being true when
//! sending shipped, while the layout it justified stayed (dig_ecosystem#2967).
//!
//! # Nothing here decides whether money may move
//!
//! Whether a send can be started, and what a finished one MEANT, is
//! [`crate::wallet::sending`]'s answer. This module draws that answer and returns the intent
//! ([`TrayAction::SendXch`]); it re-derives no rule, because a rule living in a pane is a rule no
//! test can put a wrong input in front of.
//!
//! # The rule this pane cannot break
//!
//! **No figure on this tab is divided here.** Every amount goes through
//! [`crate::amount::format_asset_amount`] (via [`crate::wallet::overview::format_amount`]), which is
//! the one place that knows $DIG is a CAT with three decimals and XCH has twelve. A local divisor is
//! what rendered $DIG a billion times too small in dig_ecosystem#2295, and a wrong balance is the one
//! defect on this surface that is worse than an absent one.
//!
//! # And the rule underneath it
//!
//! An unknown balance is never PRESENTED as a figure. [`BalanceReading`] has three states and this
//! pane renders each as itself: a reading becomes two figures, a read in flight becomes the sentence
//! saying so, and an unknown becomes a `Value::Unknown` naming which thing is missing — the same
//! sentences the tray's wallet window shows, from [`crate::wallet::overview`], so the two surfaces
//! cannot drift.
//!
//! Said that precisely, because the stronger form is false. Every non-reading is a `Value::Unknown`,
//! and the eleven reasons whose words this crate writes carry no digit at all — but
//! [`BalanceUnknown::ReadFailed`](crate::wallet::overview::BalanceUnknown::ReadFailed) quotes the
//! node, and a node says things like *rpc error 500 after 30s*. Those numerals arrive inside a
//! sentence beginning `Not known —`, never beside an asset label.

use dig_account::TransferRequest;

use super::action;
use super::card;
use super::copy;
use super::data::{self, Readout, Tone, Value};
use super::facts::{AccountKind, PaneFacts};
use super::field;
use super::flow::Flow;
use super::identity;
use super::text;
use crate::confirm::gui::paint;
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::tray_menu::TrayAction;
use crate::wallet::overview::{
    address_line, as_of_sentence, format_amount, is_syncing, unknown_reason, AddressReading,
    BalanceReading, Balances,
};
use crate::wallet::send::DEFAULT_SEND_FEE_MOJOS;
use crate::wallet::sending::{SendBlocked, SendDraft, SendProgress};
use crate::wallet::state::Asset;
use crate::window_model::Tab;

/// Draw the Wallet pane's content into `flow`, and report the action pressed.
///
/// # The order, and why it is this one (dig_ecosystem#2967)
///
/// The balance leads, then the two verbs, then whichever verb's card is open. That is the inverse
/// of what this tab shipped with: the address and its ~270 px code were the first card, so the
/// figure a person opens a wallet to read sat below the fold in body-sized type while a code nobody
/// scans twice a month owned the first screenful.
///
/// The header of that older arrangement — *"receiving is the one thing this wallet can do today"* —
/// stopped being true when sending shipped, and the layout it justified outlived it.
pub(crate) fn draw(
    flow: &mut Flow,
    t: &Tokens,
    tab: &Tab,
    facts: &PaneFacts,
) -> Option<TrayAction> {
    balance_card(flow, t, &facts.balance, facts);
    flow.gap(space::S4);

    let mut open = Disclosed::load(flow);
    if let Some(pressed) = verbs_row(flow, t, facts, open) {
        open = open.toggled(pressed);
        Disclosed::store(flow, open);
    }

    // Asked ONCE and used for both the card and the verb filter below, so the two cannot come to
    // disagree about whether the receive card is on screen. Consulting `open` alone would gap for a
    // card that then early-returns on an address it cannot show, leaving a hole and a stale-open bit.
    let showing_receive = drew_copy_control(facts, open);
    if showing_receive {
        flow.gap(space::S4);
        if receive_card(flow, t, facts) {
            open = Disclosed::Nothing;
            Disclosed::store(flow, open);
        }
    }

    // The sending card is drawn when its verb is open, AND whenever a payment is in flight whether
    // or not anybody opened it. A settling payment is the newest thing on the tab and must not be
    // reachable only by remembering to press something.
    let disclosed_send = open == Disclosed::Send;
    let sent = match disclosed_send || !matches!(facts.send, SendProgress::Idle) {
        true => {
            flow.gap(space::S4);
            let (sent, done) = sending_card(flow, t, facts, disclosed_send);
            if done {
                Disclosed::store(flow, Disclosed::Nothing);
            }
            sent
        }
        false => None,
    };

    flow.gap(space::S4);
    // The tab's own verbs, LAST and in a card of their own — but only where the model offers one
    // this pane has not already drawn. See [`spare_verbs`].
    //
    // A press on Send wins over anything below it: both cannot happen in one frame, and an `or` here
    // would drop the intent a person actually expressed if a verb were ever pressed alongside it.
    // `showing_receive`, not a fresh `drew_copy_control(facts, open)`: closing the card above moves
    // `open` on, and re-asking would report no copy control on the very frame one was drawn — putting
    // the menu's row back beside it and offering the same verb twice.
    sent.or(spare_verbs_card(flow, t, tab, showing_receive))
}

/// Which of the tab's two disclosed cards is showing.
///
/// # Why one at a time
///
/// Sending and receiving are opposite errands and nobody is on both at once, so a person who opens
/// one has finished with the other. Holding both open would also put the send form below a 220 px
/// code on a 480 px window, which is the burial this redesign exists to undo.
///
/// # Why this is not a modal
///
/// A modal is what a person familiar with other wallets would expect, and the pane system has no
/// way to draw one: `window/shell.rs` reserves its scrim and overlay for consent prompts driven by
/// `ActivePrompt`, and a pane cannot raise one. Building an in-pane overlay would mean escaping the
/// scroll area the pane lives inside — a new primitive, for one surface, on the money tab.
///
/// Disclosure buys the thing that actually mattered: the code stops being permanent furniture and
/// becomes something summoned for the seconds it is wanted. The rest is a window-manager detail the
/// person does not experience.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Disclosed {
    /// Neither card is open — the resting state, and what the tab shows on arrival.
    #[default]
    Nothing,
    /// The address, its code and the copy control.
    Receive,
    /// The send form.
    Send,
}

impl Disclosed {
    /// The id this tab's disclosure is remembered under.
    ///
    /// Stable across frames and named for the tab, in the idiom `settings::Session` uses: an
    /// immediate-mode pane holds no state of its own, so what is open lives in egui's per-context
    /// store and is read back the next frame.
    fn element() -> egui::Id {
        egui::Id::new("dig-window-wallet-disclosed")
    }

    /// What is open right now.
    fn load(flow: &mut Flow) -> Self {
        flow.place(|ui, _| {
            (
                0.0,
                ui.data(|d| d.get_temp(Self::element())).unwrap_or_default(),
            )
        })
    }

    /// Remember what is open, so the next frame draws it.
    fn store(flow: &mut Flow, open: Self) {
        flow.place(|ui, _| {
            ui.data_mut(|d| d.insert_temp(Self::element(), open));
            (0.0, ())
        });
    }

    /// The state after pressing `verb`.
    ///
    /// Pressing the verb whose card is already open CLOSES it, which is the second way out of a
    /// disclosed card — `professional-ui`'s never-trap rule wants one that is visible from inside
    /// (the Done control) and one where the person last clicked.
    fn toggled(self, verb: Verb) -> Self {
        match (self, verb) {
            (Self::Receive, Verb::Receive) | (Self::Send, Verb::Send) => Self::Nothing,
            (_, Verb::Receive) => Self::Receive,
            (_, Verb::Send) => Self::Send,
        }
    }
}

/// The two things a person came to this tab to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    /// Let me pay somebody.
    Send,
    /// Show me my address.
    Receive,
}

/// The tab's two verbs side by side, and the reason under whichever one is refused.
///
/// # Why a refused verb is drawn at all
///
/// Removing Send from a locked wallet would leave a tab whose controls change shape with the
/// account state, and a person who cannot find Send does not conclude *my account is locked* — they
/// conclude the app cannot send. So both verbs are always present, and a refused one is a `Ghost`
/// that states its condition underneath, the same treatment the form's own submit already uses.
///
/// # Which refusals belong here
///
/// Only refusals about the WALLET: a sealed account, and a payment already running. A missing
/// destination is not a reason to withhold the form that collects one — that refusal belongs to the
/// submit control inside, where [`send_form`] already draws it against the field it is about.
fn verbs_row(flow: &mut Flow, t: &Tokens, facts: &PaneFacts, open: Disclosed) -> Option<Verb> {
    let send_refusal = send_refusal(facts);
    let receive_refusal = receive_refusal(facts);
    let live = flow.live();

    let verbs = vec![
        action::Action {
            label: copy::wallet::SEND_BUTTON_OPEN.to_string(),
            // The lead verb, and the one place this pane names a primary: `action::weigh` never
            // returns `Primary` precisely so that a pane has to choose deliberately. A refused verb
            // is never the lead — a bright control that will not answer is the defect that rule
            // exists for (dig_ecosystem#2354).
            weight: match send_refusal.is_none() && open != Disclosed::Send {
                true => Weight::Primary,
                false => Weight::Ghost,
            },
            enabled: send_refusal.is_none(),
            id: Verb::Send,
            element: egui::Id::new("dig-window-wallet-verb-send"),
        },
        action::Action {
            label: copy::wallet::RECEIVE_BUTTON.to_string(),
            weight: Weight::Ghost,
            enabled: receive_refusal.is_none(),
            id: Verb::Receive,
            element: egui::Id::new("dig-window-wallet-verb-receive"),
        },
    ];

    let pressed = flow.place(|ui, at| action::buttons(ui, at, t, live, &verbs));

    for sentence in [send_refusal, receive_refusal].into_iter().flatten() {
        flow.gap(space::S2);
        flow.place(|ui, at| (text::caption(ui, at, t, &sentence), ()));
    }
    pressed
}

/// Why Send cannot be opened, or `None` when it can.
///
/// Assessed through [`SendDraft`] rather than by re-reading the account state, because whether a
/// send may START is [`crate::wallet::sending`]'s answer and a second copy of that rule here is a
/// rule no test can put a wrong input in front of. The draft is assessed with the fields EMPTY —
/// the form has not been opened yet — so the two field-shaped refusals it returns are the expected
/// answer rather than a reason to withhold the form, and [`state_of`] is what tells them apart.
fn send_refusal(facts: &PaneFacts) -> Option<String> {
    let blocked = SendDraft {
        destination: "",
        amount: "",
        account_open: matches!(facts.account, Some(AccountKind::Unlocked)),
        balance: &facts.balance,
        progress: &facts.send,
    }
    .assess()
    .err()?;
    match matches!(
        blocked,
        SendBlocked::AccountSealed | SendBlocked::AlreadySending
    ) {
        true => Some(blocked.sentence()),
        false => None,
    }
}

/// Why Receive cannot be opened, or `None` when it can.
///
/// The sentence is [`address_line`]'s, so a refused Receive names the remedy for THIS account's
/// state — set up an account, choose a password, unlock — rather than a generic unavailability.
///
/// # Why it carries no prefix
///
/// It briefly had one, matching [`copy::wallet::BALANCE_NOT_KNOWN`]'s *"Not known —"*. That pairing
/// works there because `unknown_reason` writes CLAUSES to complete, and it fails here because
/// `address_line` writes whole sentences: the result read *"No address yet — Your address is not
/// shown because your account is locked"*, which states the same fact twice and capitalises
/// mid-sentence. The sentence is already self-contained, so it is shown as it is.
fn receive_refusal(facts: &PaneFacts) -> Option<String> {
    match address_of(facts) {
        AddressReading::Known(_) => None,
        unavailable => Some(address_line(&unavailable)),
    }
}

/// The address money arrives at: the code, the value, and the way to lift it off the screen.
///
/// Returns whether the reader asked to close it.
///
/// # Why the reason for an absent address is no longer drawn here
///
/// It used to be, and it was right while this card was drawn unconditionally at the top of the tab:
/// a person who opened Wallet and found no mention of an address learned nothing, so the reason they
/// had none was the most useful thing on the page.
///
/// The card is now DISCLOSED, and a disclosure whose control is refused never opens — so a sentence
/// in here would be one nobody in that state can reach. The reason moved to where the refusal is,
/// under the Receive control itself ([`receive_refusal`]), which is the same sentence in the place
/// the person is actually looking.
fn receive_card(flow: &mut Flow, t: &Tokens, facts: &PaneFacts) -> bool {
    let AddressReading::Known(address) = address_of(facts) else {
        return false;
    };
    let live = flow.live();
    flow.place(|ui, at| {
        let (height, done) =
            card::interactive_card(ui, at, t, live, Some(copy::wallet::RECEIVE_CARD), |inner| {
                known_address(inner, t, &address);
                close_control(inner, t, live, "dig-window-wallet-receive-done")
            });
        (height, done.unwrap_or(false))
    })
}

/// The code, the address and the copy control, in the order a person uses them.
fn known_address(inner: &mut Flow, t: &Tokens, address: &str) {
    let value = Value::Identifier(address.to_owned());
    let live = inner.live();
    inner.place(|ui, at| {
        (
            identity::scannable(ui, at, t, address, copy::qr::RECEIVE_CAPTION),
            (),
        )
    });
    inner.gap(space::S3);
    inner.place(|ui, at| {
        (
            identity::copyable(
                ui,
                at,
                t,
                copy::wallet::ADDRESS_LABEL,
                &value,
                egui::Id::new("dig-window-wallet-copy-address"),
                live,
            ),
            (),
        )
    });
    inner.gap(space::S2);
    inner.place(|ui, at| (text::caption(ui, at, t, copy::wallet::RECEIVE_HINT), ()));
}

/// What this account holds, or the reason there is no figure — the tab's headline card.
///
/// # Why the first figure is set at display size (dig_ecosystem#2967)
///
/// A wallet exists to answer *how much do I have?*, and this card is that answer. It used to be the
/// SECOND card on the tab, in the same body-sized type as every other readout, under a code that
/// took the whole first screen — so the one question the tab exists for was the one thing a glance
/// did not land on. The figure now leads the tab and is drawn through [`data::headline`].
///
/// # Why the rest are rows rather than a second column
///
/// [`data::readouts`] pairs items side by side once there is room, which turned two assets into a
/// single flat line about 40 px tall and put a third asset in a new place under the first. Assets
/// are a LIST — the same kind of thing, compared down a column — so they take [`data::rows`], which
/// keeps one per line at every width and does not change shape as the list grows.
///
/// # The as-of line
///
/// A shown figure is always followed by what it is true AS OF. A light client trails the chain tip
/// permanently, so the figure above is a statement about a moment rather than about now, and the
/// as-of line is what makes it a true one (dig_ecosystem#2824). It carries only its own provenance:
/// how far behind the node is, is the header strip's job, and repeating it here would say the same
/// thing twice in two voices.
fn balance_card(flow: &mut Flow, t: &Tokens, balance: &BalanceReading, facts: &PaneFacts) {
    let items = holdings(balance);
    let as_of = match balance {
        BalanceReading::Known { as_of, .. } => {
            Some(as_of_sentence(*as_of, facts.network.chia_peer_peak_height))
        }
        BalanceReading::Pending | BalanceReading::Unknown(_) => None,
    };
    let syncing = is_syncing(balance, facts.network.chia_peer_peak_height);
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::wallet::BALANCE_CARD), |inner| {
                // The badge leads the figures rather than following the sentence, because it
                // qualifies the number a glance takes and a glance stops at the number
                // (dig_ecosystem#2869). `Warn`, not `Good`: nothing is broken, but the figure is
                // not the last word yet.
                if syncing {
                    inner.place(|ui, at| {
                        (
                            data::badge(
                                ui,
                                at.left_top(),
                                t,
                                copy::wallet::BALANCE_SYNCING_BADGE,
                                Tone::Warn,
                            )
                            .height(),
                            (),
                        )
                    });
                    inner.gap(space::S2);
                }
                // The FIRST holding is the headline and the rest are rows beneath it. Which
                // holding is first stays [`holdings`]' decision — $DIG, for the reason
                // [`figures`] gives — so this card decides the treatment and never the order.
                //
                // A `let else` rather than an index or an `expect`: `holdings` returns at least one
                // item in every state, and a pane that would panic if that ever changed is a worse
                // failure than a card that comes out short.
                let Some((headline, rest)) = items.split_first() else {
                    return;
                };
                inner.place(|ui, at| (data::headline(ui, at, t, &headline.value), ()));
                if !rest.is_empty() {
                    inner.gap(space::S4);
                    inner.place(|ui, at| (data::rows(ui, at, t, rest), ()));
                }
                if let Some(sentence) = &as_of {
                    inner.gap(space::S3);
                    inner.place(|ui, at| (text::caption(ui, at, t, sentence), ()));
                }
            }),
            (),
        )
    });
}

/// The readouts for a balance reading: two figures, or one sentence.
///
/// # Why an unknown collapses to a single readout
///
/// The reason a balance is missing applies to the whole account, not to one asset — there is no state
/// in which XCH is known and $DIG is not (`read_balances` makes either failure fail both, so that a
/// half-read is never displayed as a whole one). Two rows repeating the same sentence would imply
/// two independent facts.
fn holdings(balance: &BalanceReading) -> Vec<Readout> {
    match balance {
        BalanceReading::Known { balances, .. } => figures(balances),
        BalanceReading::Pending => vec![Readout::new(
            copy::wallet::BALANCE_LABEL,
            Value::Unknown(copy::wallet::BALANCE_PENDING.to_string()),
        )],
        BalanceReading::Unknown(why) => vec![Readout::new(
            copy::wallet::BALANCE_LABEL,
            Value::Unknown(format!(
                "{} {}",
                copy::wallet::BALANCE_NOT_KNOWN,
                unknown_reason(why)
            )),
        )],
    }
}

/// The two held amounts, each formatted by the one formatter that knows its decimals.
///
/// $DIG first: it is the network's own token and the reason most people have this wallet, and XCH is
/// the fee currency beside it.
fn figures(held: &Balances) -> Vec<Readout> {
    vec![
        Readout::new(
            copy::wallet::DIG_LABEL,
            Value::Measure {
                amount: format_amount(Asset::Dig, held.dig_units),
                unit: copy::wallet::DIG_UNIT.to_string(),
            },
        ),
        Readout::new(
            copy::wallet::XCH_LABEL,
            Value::Measure {
                amount: format_amount(Asset::Xch, held.xch_mojos),
                unit: copy::wallet::XCH_UNIT.to_string(),
            },
        ),
    ]
}

/// Sending: what the last payment came to, and the form for the next one (dig_ecosystem#2819).
///
/// # Why the state sits ABOVE the form rather than replacing it
///
/// A payment that is settling, or that has just settled, is the newest thing on the page and belongs
/// where a person looks first. But it must not take the form away: what stops a second send while one
/// is running is the **Send** control being refused with its reason
/// ([`SendBlocked::AlreadySending`]), which is a sentence a person can read, where a vanished form is
/// a page that appears to have lost a feature.
///
/// Reports the action pressed, and whether the reader asked to close the card.
///
/// # When the close control is drawn, and why it takes BOTH conditions
///
/// It appears only where pressing it will visibly close this card: the card was disclosed by a
/// person AND there is no payment to report.
///
/// The idle half is the one doing the work. `disclosed` is, as the caller stands today, already
/// implied by it — [`draw`] shows this card when `disclosed_send || send != Idle`, so a card that
/// is drawn while idle can only have been drawn because somebody opened it, and the two spellings
/// are equivalent. A mutation dropping `disclosed` therefore changes no behaviour and no test
/// catches it, which is the correct outcome rather than a coverage gap.
///
/// It is kept because that equivalence is the CALLER's property, not this function's: it holds only
/// while the draw condition stays a disjunction with `disclosed_send` on one side. Stating both
/// conditions here keeps this function correct on its own terms if that ever changes, and says out
/// loud what the control means.
///
/// Without the idle check, the ORDINARY path grows a control that does nothing. Nothing on the send
/// path clears the disclosure — the submit does not touch it — so a person who opens the form and
/// sends from it still has `Disclosed::Send` set for the whole flight. The card would then draw a
/// `Done` while also being drawn for the `send != Idle` reason, and pressing it would clear the
/// disclosure and leave the card exactly where it was. That is the "control that visibly failed to
/// close anything" this doc used to name as a defect while the code committed it.
///
/// The case the parameter was added for still holds, because a sealed account has nothing in
/// flight: `Disclosed::Send` survives in egui's store, so an account sealing under an open form
/// leaves the verb that opened it refused — and without a control in here, a card nothing on the
/// tab can close (`professional-ui`, HARD RULE 1).
fn sending_card(
    flow: &mut Flow,
    t: &Tokens,
    facts: &PaneFacts,
    disclosed: bool,
) -> (Option<TrayAction>, bool) {
    let live = flow.live();
    let closable = disclosed && matches!(facts.send, SendProgress::Idle);
    flow.place(|ui, at| {
        let (height, pressed) =
            card::interactive_card(ui, at, t, live, Some(copy::wallet::SENDING_CARD), |inner| {
                if !matches!(facts.send, SendProgress::Idle) {
                    outcome(inner, t, &facts.send);
                    inner.gap(space::S4);
                }
                let pressed = send_form(inner, t, facts);
                inner.gap(space::S2);
                inner.place(|ui, at| (text::caption(ui, at, t, copy::wallet::SENDING_HINT), ()));
                let done = closable && close_control(inner, t, live, "dig-window-wallet-send-done");
                (pressed, done)
            });
        let (pressed, done) = pressed.unwrap_or((None, false));
        (height, (pressed, done))
    })
}

/// The control that closes a disclosed card. Reports whether it was pressed.
///
/// Shared by both disclosed cards so they cannot drift into two ways of saying the same thing, and
/// so neither can be given one while the other is left without — which is exactly how the send card
/// shipped without an escape while the receive card had one.
fn close_control(flow: &mut Flow, t: &Tokens, live: bool, element: &str) -> bool {
    flow.gap(space::S4);
    flow.place(|ui, at| {
        let hit = paint::button_at(
            ui,
            egui::Rect::from_min_size(
                at.left_top(),
                egui::Vec2::new(
                    paint::button_width(ui, copy::wallet::CLOSE_BUTTON),
                    paint::BUTTON_HEIGHT,
                ),
            ),
            egui::Id::new(element),
            copy::wallet::CLOSE_BUTTON,
            Weight::Ghost,
            live,
            t,
        )
        .clicked();
        (paint::BUTTON_HEIGHT, hit)
    })
}

/// What became of the payment in flight, drawn as the state it actually is.
///
/// Each state gets its own badge word, its own sentence and its own facts, because they call for
/// different things: waiting, doing nothing, watching, or reading a reason. The two that a surface is
/// most tempted to merge are kept furthest apart — `Unknown` is not a failure, and says so.
fn outcome(flow: &mut Flow, t: &Tokens, send: &SendProgress) {
    let (word, tone, body) = match send {
        SendProgress::Idle => return,
        SendProgress::Signing => (
            copy::wallet::SEND_SIGNING_BADGE,
            Tone::Neutral,
            copy::wallet::SEND_SIGNING_BODY.to_string(),
        ),
        SendProgress::Pending {
            blocks_since_push, ..
        } => (
            copy::wallet::SEND_PENDING_BADGE,
            Tone::Neutral,
            copy::wallet::send_pending_body(*blocks_since_push),
        ),
        SendProgress::Unknown { detail, .. } => (
            copy::wallet::SEND_UNKNOWN_BADGE,
            Tone::Warn,
            copy::wallet::send_unknown_body(detail),
        ),
        SendProgress::Confirmed { .. } => (
            copy::wallet::SEND_CONFIRMED_BADGE,
            Tone::Good,
            copy::wallet::SEND_CONFIRMED_BODY.to_string(),
        ),
        // The two failures are NOT the same statement. One never reached the network and may promise
        // that no money moved; the other was broadcast and ruled out by a coin being spent elsewhere,
        // which is a thing that happened on chain. Saying "nothing was sent" there would be a lie
        // about money, so each gets its own words.
        SendProgress::Failed {
            reason,
            payment_coin_id: None,
        } => (
            copy::wallet::SEND_FAILED_BADGE,
            Tone::Warn,
            format!("{} {reason}", copy::wallet::SEND_FAILED_BODY),
        ),
        SendProgress::Failed {
            reason,
            payment_coin_id: Some(_),
        } => (
            copy::wallet::SEND_DIED_BADGE,
            Tone::Warn,
            format!("{} {reason}", copy::wallet::SEND_DIED_BODY),
        ),
        // Drawn as its own state and NEVER through `SEND_FAILED_BODY`: this app crashing is not
        // evidence that no money moved (dig_ecosystem#2895).
        SendProgress::Abandoned { detail } => (
            copy::wallet::SEND_ABANDONED_BADGE,
            Tone::Warn,
            copy::wallet::send_abandoned_body(detail),
        ),
    };

    flow.place(|ui, at| (data::badge(ui, at.left_top(), t, word, tone).height(), ()));
    flow.gap(space::S3);
    flow.place(|ui, at| (text::body(ui, at, t, &body), ()));

    let facts = outcome_facts(send);
    if !facts.is_empty() {
        flow.gap(space::S3);
        flow.place(|ui, at| (data::readouts(ui, at, t, &facts), ()));
    }
}

/// The identifiers a person can take away from a payment: the coin, and the block it settled at.
///
/// A payment coin id is what makes an unknown outcome watchable by somebody other than this app, and
/// it is the one thing worth carrying to a block explorer — so it is shown for every state that has
/// one, not only the happy ones.
fn outcome_facts(send: &SendProgress) -> Vec<Readout> {
    match send {
        SendProgress::Idle
        | SendProgress::Signing
        // A panic produces no payment coin, so there is nothing to offer for lookup — which is
        // exactly why this state cannot be `Unknown`.
        | SendProgress::Abandoned { .. }
        | SendProgress::Failed {
            payment_coin_id: None,
            ..
        } => Vec::new(),
        SendProgress::Pending {
            payment_coin_id, ..
        }
        | SendProgress::Unknown {
            payment_coin_id, ..
        }
        // A payment that died AFTER being pushed has a real coin, and that is exactly when a person
        // most needs something to look up. Withholding it here left them with a verdict and no way
        // to check it.
        | SendProgress::Failed {
            payment_coin_id: Some(payment_coin_id),
            ..
        } => vec![Readout::new(
            copy::wallet::SEND_COIN_LABEL,
            Value::Identifier(payment_coin_id.clone()),
        )],
        SendProgress::Confirmed {
            payment_coin_id,
            confirmed_height,
        } => vec![
            Readout::new(
                copy::wallet::SEND_COIN_LABEL,
                Value::Identifier(payment_coin_id.clone()),
            ),
            Readout::new(
                copy::wallet::SEND_HEIGHT_LABEL,
                Value::Word(confirmed_height.to_string()),
            ),
        ],
    }
}

/// The two fields, the fee, and the control — or the reason the control cannot be pressed.
///
/// The typed values live in egui's per-frame store keyed off this pane's own id, the same way the
/// Content tab's add-a-store field does, so the caret and the text survive the pane being rebuilt
/// every frame without this module holding state of its own.
fn send_form(flow: &mut Flow, t: &Tokens, facts: &PaneFacts) -> Option<TrayAction> {
    let element = egui::Id::new("dig-window-wallet-send");
    let live = flow.live();
    let (mut destination, mut amount) = typed(flow, element);

    let verdict = SendDraft {
        destination: &destination,
        amount: &amount,
        account_open: matches!(facts.account, Some(AccountKind::Unlocked)),
        balance: &facts.balance,
        progress: &facts.send,
    }
    .assess();

    flow.place(|ui, at| {
        (
            field::text_field(
                ui,
                at,
                t,
                live,
                &field::Field {
                    label: copy::wallet::SEND_TO_LABEL,
                    placeholder: copy::wallet::SEND_TO_PLACEHOLDER,
                    help: copy::wallet::SEND_TO_HINT,
                    error: field_error(&verdict, Field::Destination),
                    id: element.with("to"),
                },
                &mut destination,
            ),
            (),
        )
    });
    flow.gap(space::S3);
    flow.place(|ui, at| {
        (
            field::text_field(
                ui,
                at,
                t,
                live,
                &field::Field {
                    label: copy::wallet::SEND_AMOUNT_LABEL,
                    placeholder: copy::wallet::SEND_AMOUNT_PLACEHOLDER,
                    help: copy::wallet::SEND_AMOUNT_HINT,
                    error: field_error(&verdict, Field::Amount),
                    id: element.with("amount"),
                },
                &mut amount,
            ),
            (),
        )
    });
    remember(flow, element, &destination, &amount);

    flow.gap(space::S2);
    // The fee is drawn through the one formatter that knows XCH has twelve decimal places. A figure
    // divided here would be the money lie this pane's module doc forbids, in the one place a person
    // is deciding what a payment costs.
    let fee = format_amount(Asset::Xch, DEFAULT_SEND_FEE_MOJOS);
    flow.place(|ui, at| (text::caption(ui, at, t, &copy::wallet::send_fee(&fee)), ()));
    flow.gap(space::S3);

    let pressed = flow.place(|ui, at| {
        let hit = paint::button_at(
            ui,
            egui::Rect::from_min_size(
                at.left_top(),
                egui::Vec2::new(
                    paint::button_width(ui, copy::wallet::SEND_BUTTON),
                    paint::BUTTON_HEIGHT,
                ),
            ),
            element.with("submit"),
            copy::wallet::SEND_BUTTON,
            match verdict.is_ok() {
                // The one thing a person comes to this card to do, so it leads — but only while it
                // can actually be pressed. A bright control that refuses is the defect
                // `action::weigh` describes.
                true => Weight::Primary,
                false => Weight::Ghost,
            },
            verdict.is_ok() && live,
            t,
        )
        .clicked();
        (paint::BUTTON_HEIGHT, hit)
    });

    // The reason the control is refused, under the control. `professional-ui`'s never-trap rule: a
    // greyed button whose condition is unstated sends a person looking for it. Field-level problems
    // are already attached to their own field, so they are not repeated here.
    if let Err(blocked) = &verdict {
        if state_of(blocked) {
            flow.gap(space::S2);
            let sentence = blocked.sentence();
            flow.place(|ui, at| (text::caption(ui, at, t, &sentence), ()));
        }
    }

    match pressed {
        true => verdict.ok().map(TrayAction::SendXch),
        false => None,
    }
}

/// Which input a refusal belongs to.
enum Field {
    /// The destination.
    Destination,
    /// The amount.
    Amount,
}

/// The error to attach to `field`, if the draft's refusal is about that field.
///
/// A refusal has ONE home. Attaching every reason to every control would put "unlock your account"
/// under the amount box, and `professional-ui` is explicit that an error belongs to the control that
/// caused it.
fn field_error(verdict: &Result<TransferRequest, SendBlocked>, field: Field) -> Option<String> {
    let Err(blocked) = verdict else {
        return None;
    };
    let mine = matches!(
        (blocked, field),
        (SendBlocked::BadDestination(_), Field::Destination)
            | (
                SendBlocked::BadAmount(_) | SendBlocked::NotEnough { .. },
                Field::Amount
            )
    );
    mine.then(|| blocked.sentence())
}

/// Whether a refusal is about the STATE of the wallet rather than about a field.
///
/// The two empty-field states count as state rather than as field errors: a form that complained
/// about an empty box the moment it was drawn would be scolding somebody for opening it.
fn state_of(blocked: &SendBlocked) -> bool {
    matches!(
        blocked,
        SendBlocked::AccountSealed
            | SendBlocked::AlreadySending
            | SendBlocked::NoDestination
            | SendBlocked::BadAmount(crate::amount::AmountProblem::Empty)
    )
}

/// What is currently typed into the two fields.
///
/// Reached through a zero-height block because a [`Flow`] hands out its `Ui` only inside one — which
/// is the same reason the Content tab's field reads its own store from inside its draw call.
fn typed(flow: &mut Flow, element: egui::Id) -> (String, String) {
    flow.place(|ui, _| {
        (
            0.0,
            ui.ctx().data(|d| {
                (
                    d.get_temp(element.with("to-text")).unwrap_or_default(),
                    d.get_temp(element.with("amount-text")).unwrap_or_default(),
                )
            }),
        )
    })
}

/// Keep what was typed, so the next frame draws it back.
fn remember(flow: &mut Flow, element: egui::Id, destination: &str, amount: &str) {
    flow.place(|ui, _| {
        ui.ctx().data_mut(|d| {
            d.insert_temp(element.with("to-text"), destination.to_owned());
            d.insert_temp(element.with("amount-text"), amount.to_owned());
        });
        (0.0, ())
    })
}

/// Whatever the model puts on this tab that the pane has not already drawn as a control.
///
/// # Why the copy-address row is filtered out (dig_ecosystem#2357)
///
/// This card used to render EVERY row, and the Wallet tab's one row is `Copy my receive address` —
/// which the receive card above already offers, beside the address it copies. So the tab showed the
/// address twice and offered two ways to copy it, and the second lived in a card titled "Wallet
/// actions" that existed for no other reason than to hold it.
///
/// The row is not dropped from the product: it is the SAME verb, in the place it belongs, next to
/// the value it acts on. What is dropped is the second rendering of it. Anything else the model puts
/// here is still drawn, because a pane may not decide that a verb the model offered is not worth
/// showing.
fn spare_verbs_card(
    flow: &mut Flow,
    t: &Tokens,
    tab: &Tab,
    drew_copy_control: bool,
) -> Option<TrayAction> {
    let actions = spare_verbs(super::actions_of(tab), drew_copy_control);
    if actions.is_empty() {
        return None;
    }
    let live = flow.live();
    flow.place(|ui, at| {
        let (height, pressed) =
            card::interactive_card(ui, at, t, live, Some(copy::wallet::ACTIONS_CARD), |inner| {
                inner.place(|ui, at| action::buttons(ui, at, t, live, &actions))
            });
        (height, pressed.flatten())
    })
}

/// The tab's verbs minus the ones this pane has already drawn as part of a value.
///
/// The rule itself is [`action::without_the_one_already_drawn`], shared with the Account tab; this
/// names WHICH verb the receive card renders, and only when it actually rendered it.
fn spare_verbs(
    actions: Vec<action::Action<TrayAction>>,
    drew_copy_control: bool,
) -> Vec<action::Action<TrayAction>> {
    action::without_the_one_already_drawn(
        actions,
        drew_copy_control.then_some(TrayAction::CopyReceiveAddress),
    )
}

/// Whether the receive card drew a copy control this frame — the condition [`spare_verbs`] turns on.
///
/// Derived from the same [`address_of`] the card itself renders from AND from whether that card is
/// open, so the two cannot come to disagree about whether the control is on screen.
///
/// # Why the disclosure has to be part of this answer (dig_ecosystem#2967)
///
/// [`spare_verbs`] deletes the model's `Copy my receive address` row when this returns true, on the
/// grounds that the receive card already offers the same verb beside the value it acts on. That
/// reasoning holds only while the control is actually DRAWN. Once the card moved behind a
/// disclosure, an answer of "the address is known" would strip the row on every frame the card is
/// closed — taking the tab's only copy control off the screen and leaving a person who has not
/// pressed Receive with no way to lift their address off it.
///
/// So the closed state keeps the row and the open state drops it, and the tab offers exactly one
/// copy control at all times rather than two or none.
fn drew_copy_control(facts: &PaneFacts, open: Disclosed) -> bool {
    open == Disclosed::Receive && matches!(address_of(facts), AddressReading::Known(_))
}

/// The address reading this pane renders.
///
/// [`PaneFacts`] carries the address as an `Option`, which cannot say WHY it is absent — and the
/// reason is the useful half. So the reading is rebuilt from the same projection the tray's wallet
/// window uses, and the `Option` is only trusted for the present case.
fn address_of(facts: &PaneFacts) -> AddressReading {
    match &facts.receive_address {
        Some(address) => AddressReading::Known(address.clone()),
        None => match &facts.balance {
            // Every no-address state reaches the balance as `NoAddress(why)`, carrying the very
            // reason the address is missing — so the sentence shown is the one for this account's
            // actual state rather than a generic "not available".
            BalanceReading::Unknown(crate::wallet::overview::BalanceUnknown::NoAddress(why)) => {
                AddressReading::Unavailable(*why)
            }
            // No address AND a balance that is not blaming the address: this cannot arise from
            // `WalletOverview::of_tray`, which derives the balance FROM the address. Treated as the
            // ordinary sealed case rather than asserted, because a pane must not panic — and the
            // sentence it produces ("unlock it and it appears here") is the truthful default.
            _ => AddressReading::Unavailable(crate::wallet::overview::AddressUnavailable::Locked),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::gui::render::Weight;
    use crate::tray_menu::{AccountState, MenuRow, TrayView};
    use crate::wallet::overview::{balance_line, AddressUnavailable, BalanceUnknown};

    /// The address a live account derives.
    const ADDRESS: &str = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";

    fn facts_with(view: TrayView) -> PaneFacts {
        PaneFacts::of_tray(&view)
    }

    /// Every word the whole Wallet pane paints for `view`, at `width`.
    ///
    /// The assembled pane rather than one block, because the defect this exists to catch is not
    /// inside any single block: each of the code and the readout is right on its own, and the fault
    /// is that a card draws both.
    fn painted_pane(view: &TrayView, width: f32) -> Vec<String> {
        painted_pane_with(view, width, Disclosed::Nothing)
    }

    /// The same, with one of the tab's disclosed cards already open.
    ///
    /// The state is seeded into egui's store rather than reached by a synthetic click, for the
    /// reason `examples/pane_preview.rs` gives about captures: a click in a test frame is input
    /// this window does not otherwise receive, and the thing under test is what the pane DRAWS for
    /// a given disclosure — not how the disclosure came to be set. `Disclosed::load` reads this
    /// exact key, so a rename that broke the pairing reddens these tests rather than silently
    /// testing the closed state twice.
    fn painted_pane_with(view: &TrayView, width: f32, open: Disclosed) -> Vec<String> {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        ctx.data_mut(|d| d.insert_temp(Disclosed::element(), open));
        let model = crate::window_model::build(view);
        let tab = model
            .tab(crate::window_model::TabId::Wallet)
            .expect("Wallet renders in every state")
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
                    egui::Area::new(egui::Id::new("wallet-pane-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            let column = egui::Rect::from_min_size(
                                screen.left_top(),
                                egui::Vec2::new(width - space::S5 * 2.0, f32::INFINITY),
                            );
                            let mut flow = super::super::flow::Flow::new(ui, column, true);
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

    /// **An address the pane can show is written on the tab exactly ONCE (dig_ecosystem#2357).**
    ///
    /// The receive card offers the same value three ways — a code to scan, a readout to read, and a
    /// control to copy — and only ONE of those is text. The code used to print the address beneath
    /// itself as well, so the tab carried it twice in two faces a few lines apart, which asks a
    /// reader to compare two identifiers before trusting either.
    ///
    /// Counted over the WHOLE pane rather than one block, because a count taken inside the code
    /// block would still read 1 if the printing merely moved to the card around it — the property
    /// is about the tab, so the fixture has to be the tab. Asserted at two widths because the
    /// readout reflows below its control on a narrow column, which is a second layout path.
    #[test]
    fn the_receive_address_is_written_on_the_tab_exactly_once() {
        let view = TrayView {
            running: true,
            account: Some(AccountState::Unlocked { recoverable: true }),
            receive_address: Some(ADDRESS.to_string()),
            ..TrayView::default()
        };
        for width in [480.0, 900.0] {
            let said = painted_pane_with(&view, width, Disclosed::Receive);
            let times = said.iter().filter(|word| word.contains(ADDRESS)).count();
            assert_eq!(
                times, 1,
                "at {width} px the Wallet tab writes the address {times} times, not once: {said:?}"
            );

            // And the redesign's own property: with the card CLOSED the address is not on the tab
            // at all, so the balance rather than a code is what the first screen answers with
            // (dig_ecosystem#2967). Asserted beside the count above so a disclosure that silently
            // stopped opening cannot pass as "written once".
            let closed = painted_pane(&view, width);
            assert!(
                !closed.iter().any(|word| word.contains(ADDRESS)),
                "at {width} px a closed receive card still printed the address: {closed:?}"
            );
        }
    }

    /// **The balance is the first thing the tab says, in every state it can be in**
    /// (dig_ecosystem#2967).
    ///
    /// The inverted-hierarchy defect, pinned as an ORDER rather than as a set of present words: the
    /// old tab drew everything this one does and was still wrong, because the balance came second.
    /// So the assertion is positional — the balance card's title precedes both verbs — and it runs
    /// over a funded reading AND a not-known one, because the state with no figure is the one most
    /// likely to be quietly reordered to put something else first.
    #[test]
    fn the_balance_leads_the_tab_ahead_of_its_verbs() {
        let readings = [
            sendable(SendProgress::Idle),
            TrayView {
                running: true,
                account: Some(AccountState::Unlocked { recoverable: true }),
                receive_address: Some(ADDRESS.to_string()),
                balance: BalanceReading::Unknown(BalanceUnknown::NotSynced),
                ..TrayView::default()
            },
        ];
        for view in readings {
            for width in [480.0, 900.0] {
                let said = painted_pane(&view, width);
                let at = |needle: &str| said.iter().position(|word| word.contains(needle));
                let balance = at(copy::wallet::BALANCE_CARD)
                    .unwrap_or_else(|| panic!("the tab drew no balance card: {said:?}"));
                let send = at(copy::wallet::SEND_BUTTON_OPEN)
                    .unwrap_or_else(|| panic!("the tab drew no Send control: {said:?}"));
                let receive = at(copy::wallet::RECEIVE_BUTTON)
                    .unwrap_or_else(|| panic!("the tab drew no Receive control: {said:?}"));
                assert!(
                    balance < send && balance < receive,
                    "at {width} px the tab put its verbs ahead of the balance they act on: {said:?}"
                );
            }
        }
    }

    /// **Every** [`BalanceUnknown`] state, so a guard asserted "over all of them" is.
    ///
    /// Written out rather than derived, because the enum carries a `String` payload and cannot be
    /// enumerated — which is exactly how the earlier 7-of-12 list passed for "every reason". The
    /// list is checked against the enum's arms by
    /// [`every_unknown_reason_lists_every_arm_of_the_enum`], so adding a variant reddens this file
    /// rather than silently shrinking the guard.
    fn every_unknown_reason() -> Vec<BalanceUnknown> {
        vec![
            BalanceUnknown::NoAddress(AddressUnavailable::NoAccount),
            BalanceUnknown::NoAddress(AddressUnavailable::HostUnsupported),
            BalanceUnknown::NoAddress(AddressUnavailable::NoPasswordYet),
            BalanceUnknown::NoAddress(AddressUnavailable::Locked),
            BalanceUnknown::NoAddress(AddressUnavailable::Unopenable),
            BalanceUnknown::NoAddress(AddressUnavailable::DerivationFailed),
            BalanceUnknown::NoAddress(AddressUnavailable::WalletBehindActiveProfile),
            BalanceUnknown::NoNode,
            BalanceUnknown::NodeTimedOut,
            BalanceUnknown::NodeCannotRead,
            BalanceUnknown::NoChainSource,
            BalanceUnknown::NotSynced,
            BalanceUnknown::ReplicaHasNoData,
            BalanceUnknown::AddressesNotFollowed,
            BalanceUnknown::AwaitingNodeRestart,
            // The one arm whose sentence comes from OUTSIDE this crate, given the node text that
            // breaks a naive no-digit rule: an HTTP status and a timeout are both numerals.
            BalanceUnknown::ReadFailed("rpc error 500 after 30s".to_string()),
        ]
    }

    /// Whether a reason's sentence is the node's own words rather than this crate's.
    fn is_node_supplied(why: &BalanceUnknown) -> bool {
        matches!(why, BalanceUnknown::ReadFailed(_))
    }

    /// **A not-known balance reads as a sentence, not as a clause starting mid-thought.**
    ///
    /// Found by looking at the locked pane: `wallet::overview`'s reasons are written to complete
    /// "Balance: not known — ", so under a bare `Balance` label they began in lower case — *"your
    /// account is locked, so DIG cannot tell which address to read."* Reusing those sentences is
    /// right; presenting them without the words they complete was not. Asserted over EVERY reason
    /// the enum has, because one arm fixed by hand is one arm.
    ///
    /// The second assertion is what an earlier `first.is_uppercase()` could not be: that check read
    /// the first character of the `Not known —` CONSTANT, so it passed whatever the reason did —
    /// including for a pane that rendered the prefix and dropped the reason entirely. That is the
    /// nearest wrong implementation, so the clause AFTER the prefix is what is asserted here.
    #[test]
    fn a_not_known_balance_supplies_the_words_its_reason_completes() {
        for why in every_unknown_reason() {
            let shown = holdings(&BalanceReading::Unknown(why.clone()))[0]
                .value
                .shown()
                .to_string();
            assert!(
                shown.starts_with(copy::wallet::BALANCE_NOT_KNOWN),
                "{why:?} renders as a bare clause: {shown}"
            );
            let clause = shown[copy::wallet::BALANCE_NOT_KNOWN.len()..].trim();
            assert!(
                !clause.is_empty(),
                "{why:?} rendered a prefix with nothing after it: {shown}"
            );
            assert_eq!(
                clause,
                unknown_reason(&why).trim(),
                "{why:?} rendered the prefix without the reason it introduces"
            );
        }
    }

    /// **No reason reaches the pane carrying a run of spaces.**
    ///
    /// egui does not collapse whitespace, so a multi-space run in a source literal is rendered
    /// verbatim to the user — a ragged gap mid-sentence on the money surface. It is produced by the
    /// ordinary mistake of wrapping a long literal across source lines without the trailing
    /// backslash the neighbouring arms use, and it is invisible in a diff.
    ///
    /// Asserted over the WHOLE reason list and over BOTH sentence functions rather than one, because
    /// this defect class has now appeared three times in two days in this file family: a guard added
    /// for one function did not catch two later instances in its sibling, which is the entire reason
    /// it is written this way. It also checks the pane's own rendering, so a gap introduced between
    /// the prefix and the reason is caught alongside one inside a literal.
    ///
    /// The control is the assertion's own subject: every reason is a real multi-word sentence, so a
    /// vacuous pass would need the list to be empty — which
    /// `every_unknown_reason_lists_every_arm_of_the_enum` independently forbids.
    ///
    /// # The mechanism, so the next person does not reach for the wrong fix
    ///
    /// The backslash-continuation idiom the neighbouring arms use is correct but NOT durable:
    /// `cargo fmt` joins a continued literal back onto one physical line when the result fits inside
    /// `max_width`, and the join keeps the continuation's indentation as literal spaces while the
    /// backslash disappears. So a sentence can acquire this defect from a formatting run alone,
    /// without anyone editing it. That is why the guard is mechanical rather than a review habit.
    #[test]
    fn no_reason_renders_a_run_of_spaces() {
        for why in every_unknown_reason() {
            let rendered = holdings(&BalanceReading::Unknown(why.clone()))[0]
                .value
                .shown()
                .to_string();
            for (source, text) in [
                ("unknown_reason", unknown_reason(&why)),
                (
                    "menu_reason",
                    balance_line(&BalanceReading::Unknown(why.clone()), None),
                ),
                ("the pane", rendered),
            ] {
                assert!(
                    !text.contains("  "),
                    "{source} gives {why:?} a run of spaces egui will render verbatim: {text:?}"
                );
                assert!(
                    !text.contains(
                        " 
"
                    ) && !text.contains("	"),
                    "{source} gives {why:?} stray whitespace: {text:?}"
                );
            }
        }
    }

    /// **A held amount is rendered by the shared formatter, at the asset's own scale.**
    ///
    /// The fixture is the defect dig_ecosystem#2295 fixed: one whole $DIG is 1,000 base units and one
    /// whole XCH is 10^12 mojos, so a pane that used ONE divisor for both — or the wrong one for
    /// either — renders a figure that is off by nine orders of magnitude while still looking like a
    /// balance. Both assets are asserted, and with amounts whose correct renderings are equal ("1"),
    /// so a swapped-asset bug cannot hide behind two different-looking numbers being present.
    #[test]
    fn each_asset_is_scaled_by_its_own_decimals() {
        let items = figures(&Balances {
            xch_mojos: 1_000_000_000_000,
            dig_units: 1_000,
        });
        let shown = |label: &str| {
            items
                .iter()
                .find(|item| item.label == label)
                .map(|item| item.value.clone())
                .expect("the readout exists")
        };
        assert_eq!(
            shown(copy::wallet::DIG_LABEL),
            Value::Measure {
                amount: "1".to_string(),
                unit: copy::wallet::DIG_UNIT.to_string()
            }
        );
        assert_eq!(
            shown(copy::wallet::XCH_LABEL),
            Value::Measure {
                amount: "1".to_string(),
                unit: copy::wallet::XCH_UNIT.to_string()
            }
        );
    }

    /// **A sub-unit amount keeps its fraction rather than being rounded into a whole.**
    ///
    /// The companion to the test above, and the one a hardcoded `"1"` cannot satisfy: 1 base unit of
    /// $DIG is 0.001 and 1 mojo is a twelfth-place fraction. A formatter reached through the wrong
    /// divisor gets both of these visibly wrong.
    #[test]
    fn a_fraction_of_an_asset_survives_formatting() {
        let items = figures(&Balances {
            xch_mojos: 1,
            dig_units: 1,
        });
        assert_eq!(items[0].value.shown(), "0.001");
        assert_eq!(items[1].value.shown(), "0.000000000001");
    }

    /// **No balance state that is not a reading is presented as a figure.**
    ///
    /// The money-lie guard, asserted over EVERY non-`Known` state — all twelve `BalanceUnknown`
    /// arms plus `Pending` — rather than over a sample. It is stated in two parts because the arms
    /// are not alike, and the earlier single "contains no digit" rule was only ever true of the
    /// eleven arms this crate writes the words for:
    ///
    /// - **Every** state renders as a `Value::Unknown` — never a `Measure` or a `Word` — so nothing
    ///   here can be read as an amount whatever its text says. This is the load-bearing half.
    /// - The eleven arms whose sentence THIS crate authors additionally contain no digit at all,
    ///   because a stray numeral in copy under a `Balance` label is how "not known" is read as
    ///   "you hold nothing".
    /// - `ReadFailed` carries the node's own words, which legitimately contain numerals — an HTTP
    ///   status, a timeout. It is asserted instead to be `Unknown` and prefixed `Not known —`, so
    ///   its digits arrive inside a sentence about a failure rather than beside an asset label.
    #[test]
    fn nothing_but_a_reading_is_presented_as_a_figure() {
        let mut not_readings = vec![BalanceReading::Pending];
        not_readings.extend(
            every_unknown_reason()
                .into_iter()
                .map(BalanceReading::Unknown),
        );

        for reading in &not_readings {
            let items = holdings(reading);
            assert_eq!(items.len(), 1, "{reading:?} rendered more than one readout");
            assert!(
                !items[0].value.is_known(),
                "{reading:?} rendered as a known value"
            );
            let shown = items[0].value.shown().to_string();

            let quotes_the_node =
                matches!(reading, BalanceReading::Unknown(why) if is_node_supplied(why));
            if quotes_the_node {
                assert!(
                    shown.starts_with(copy::wallet::BALANCE_NOT_KNOWN),
                    "{reading:?} put the node's words under a balance label without saying the balance is not known: {shown}"
                );
                assert!(
                    shown.chars().any(|c| c.is_ascii_digit()),
                    "the fixture lost its numerals, so this arm no longer tells the no-digit rule apart from the presented-as-unknown one: {shown}"
                );
            } else {
                assert!(
                    !shown.chars().any(|c| c.is_ascii_digit()),
                    "{reading:?} put a numeral where a person reads a balance: {shown}"
                );
            }
        }

        // A real reading, by contrast, DOES produce figures — without this the assertions above are
        // satisfied by a `holdings` that never returns a number at all.
        let known = holdings(&BalanceReading::Known {
            balances: Balances {
                xch_mojos: 1_000_000_000_000,
                dig_units: 2_000,
            },
            as_of: crate::wallet::engine::BalanceAsOf::Replica {
                height: 7_000_000,
                caught_up: true,
            },
        });
        assert_eq!(known.len(), 2);
        assert!(known.iter().all(|item| item.value.is_known()));
    }

    /// **The reason list these guards run over is the whole enum.**
    ///
    /// [`every_unknown_reason`] is hand-written, so nothing stops it going stale the day a variant
    /// is added — which is precisely how the earlier guard came to cover 7 of 12 while its comment
    /// said "every". This match has no wildcard: a new arm fails to compile here first.
    #[test]
    fn every_unknown_reason_lists_every_arm_of_the_enum() {
        fn arm(why: &BalanceUnknown) -> u8 {
            match why {
                BalanceUnknown::NoAddress(AddressUnavailable::NoAccount) => 0,
                BalanceUnknown::NoAddress(AddressUnavailable::HostUnsupported) => 1,
                BalanceUnknown::NoAddress(AddressUnavailable::NoPasswordYet) => 2,
                BalanceUnknown::NoAddress(AddressUnavailable::Locked) => 3,
                BalanceUnknown::NoAddress(AddressUnavailable::Unopenable) => 4,
                BalanceUnknown::NoAddress(AddressUnavailable::DerivationFailed) => 5,
                BalanceUnknown::NoAddress(AddressUnavailable::WalletBehindActiveProfile) => 6,
                BalanceUnknown::NoNode => 7,
                BalanceUnknown::NodeTimedOut => 8,
                BalanceUnknown::NodeCannotRead => 9,
                BalanceUnknown::NoChainSource => 10,
                BalanceUnknown::NotSynced => 11,
                BalanceUnknown::ReplicaHasNoData => 12,
                BalanceUnknown::AddressesNotFollowed => 13,
                BalanceUnknown::AwaitingNodeRestart => 14,
                BalanceUnknown::ReadFailed(_) => 15,
            }
        }
        let mut arms: Vec<u8> = every_unknown_reason().iter().map(arm).collect();
        arms.sort_unstable();
        arms.dedup();
        assert_eq!(
            arms,
            (0..16).collect::<Vec<u8>>(),
            "the guard's reason list is not the whole enum"
        );
    }

    /// **Each not-known reason says something different from the others.**
    ///
    /// Reasons that all read alike are one reason wearing twelve names, and these call for different
    /// responses — set up an account, choose a password, unlock, start a node, wait, upgrade,
    /// connect the node to the chain. Asserted over the WHOLE enum, so a new reason cannot be given
    /// an existing sentence.
    #[test]
    fn every_not_known_reason_is_distinguishable() {
        let mut sentences: Vec<String> = every_unknown_reason()
            .iter()
            .map(|why| {
                holdings(&BalanceReading::Unknown(why.clone()))[0]
                    .value
                    .shown()
                    .to_string()
            })
            .collect();
        sentences.push(copy::wallet::BALANCE_PENDING.to_string());
        let total = sentences.len();
        sentences.sort();
        sentences.dedup();
        assert_eq!(
            sentences.len(),
            total,
            "two balance states are shown the same sentence"
        );
    }

    /// **A locked account's card explains the lock; an account that cannot open is not told to
    /// unlock.**
    ///
    /// Two actors, differing only in account state, because a card that showed ONE sentence for
    /// every absent address would satisfy a single-state test while naming a remedy the second user
    /// cannot perform — which is the dead end dig_ecosystem#1800 removed from the tray.
    #[test]
    fn an_absent_address_names_the_remedy_for_its_own_state() {
        let reading = |account: AccountState| {
            address_of(&facts_with(TrayView {
                account: Some(account),
                ..TrayView::default()
            }))
        };
        assert_eq!(
            reading(AccountState::Locked),
            AddressReading::Unavailable(AddressUnavailable::Locked)
        );
        assert_eq!(
            reading(AccountState::Unopenable),
            AddressReading::Unavailable(AddressUnavailable::Unopenable)
        );
        assert_eq!(
            reading(AccountState::NeedsPassword),
            AddressReading::Unavailable(AddressUnavailable::NoPasswordYet)
        );
        assert_eq!(
            reading(AccountState::Absent),
            AddressReading::Unavailable(AddressUnavailable::NoAccount)
        );
        // And the present case, so the mapping is not simply "always unavailable".
        assert_eq!(
            address_of(&facts_with(TrayView {
                account: Some(AccountState::Unlocked { recoverable: true }),
                receive_address: Some(ADDRESS.to_string()),
                ..TrayView::default()
            })),
            AddressReading::Known(ADDRESS.to_string())
        );
    }

    /// **Copy-address is offered exactly ONCE — never twice, and never zero times.**
    ///
    /// dig_ecosystem#2357's wallet half, and the trap dig_ecosystem#2967 put inside it. THREE
    /// actors now, because the disclosure added a third state that the original pair cannot see:
    ///
    /// - an open account with the receive card DISCLOSED draws the copy control beside the address,
    ///   so the model's row must not be drawn a second time in a card of its own;
    /// - an open account with the card CLOSED draws no copy control anywhere, so the row is the only
    ///   rendering there is — this is the state a predicate of "the address is known" gets wrong,
    ///   and getting it wrong takes the tab's only copy control off the screen;
    /// - a SEALED account has no address to copy, and the row (disabled, by the model) is again the
    ///   only rendering there is.
    ///
    /// The middle actor is the whole point. Before the disclosure it did not exist, so a predicate
    /// that ignored `open` passed the original two-actor test while silently deleting a verb.
    #[test]
    fn copy_address_is_drawn_once_and_never_removed_from_a_pane_that_has_no_other_copy() {
        let open = facts_with(TrayView {
            running: true,
            account: Some(AccountState::Unlocked { recoverable: true }),
            receive_address: Some(ADDRESS.to_string()),
            ..TrayView::default()
        });
        let sealed = facts_with(TrayView {
            running: true,
            account: Some(AccountState::Locked),
            ..TrayView::default()
        });
        assert!(
            drew_copy_control(&open, Disclosed::Receive),
            "a disclosed receive card draws a copy control, so the model's row is a second one"
        );
        assert!(
            !drew_copy_control(&open, Disclosed::Nothing),
            "a CLOSED receive card draws no copy control, so the model's row is the only one left \
             and stripping it leaves the tab with no way to copy an address it is holding"
        );
        assert!(
            !drew_copy_control(&sealed, Disclosed::Receive),
            "an account with no address cannot have drawn a control that copies one"
        );

        let offered = |view: TrayView| {
            let model = crate::window_model::build(&view);
            super::super::actions_of(
                model
                    .tab(crate::window_model::TabId::Wallet)
                    .expect("the Wallet tab exists"),
            )
        };
        let open_rows = offered(TrayView {
            running: true,
            account: Some(AccountState::Unlocked { recoverable: true }),
            receive_address: Some(ADDRESS.to_string()),
            ..TrayView::default()
        });
        let sealed_rows = offered(TrayView {
            running: true,
            account: Some(AccountState::Locked),
            ..TrayView::default()
        });
        for rows in [&open_rows, &sealed_rows] {
            assert!(
                rows.iter().any(|a| a.id == TrayAction::CopyReceiveAddress),
                "the model stopped offering the row this test is about"
            );
        }

        assert!(
            !spare_verbs(open_rows, true)
                .iter()
                .any(|a| a.id == TrayAction::CopyReceiveAddress),
            "an open account is offered two ways to copy one address, and the second lives in a \
             card that exists only to hold it"
        );
        assert!(
            spare_verbs(sealed_rows, false)
                .iter()
                .any(|a| a.id == TrayAction::CopyReceiveAddress),
            "a sealed account lost the only copy control on the tab"
        );
    }

    /// **Every disclosed card closes from the control that opened it** (`professional-ui`, HARD
    /// RULE 1: never trap the user).
    ///
    /// A disclosure is a blocking element in miniature — it takes over the space below the verbs —
    /// so it needs a way out. There are two, and this pins the one a person reaches for first:
    /// pressing the verb again. The Done control inside the card is the second, and is what a
    /// reader who scrolled past the verb row can see.
    ///
    /// Asserted over BOTH verbs and in both directions, because a toggle written as "open the one
    /// pressed" is the nearest wrong implementation and it traps whichever card is showing.
    #[test]
    fn every_disclosed_card_closes_from_the_control_that_opened_it() {
        for (verb, opened) in [
            (Verb::Send, Disclosed::Send),
            (Verb::Receive, Disclosed::Receive),
        ] {
            assert_eq!(
                Disclosed::Nothing.toggled(verb),
                opened,
                "{verb:?} did not open its own card"
            );
            assert_eq!(
                opened.toggled(verb),
                Disclosed::Nothing,
                "{verb:?} could not close the card it had just opened, so a person who opened it \
                 has no way back to the tab"
            );
        }
        // And the two are mutually exclusive: opening one closes the other rather than stacking a
        // 220 px code above the send form on a 480 px window.
        assert_eq!(Disclosed::Receive.toggled(Verb::Send), Disclosed::Send);
        assert_eq!(Disclosed::Send.toggled(Verb::Receive), Disclosed::Receive);
    }

    /// **Every disclosed card DRAWS a way out, including one whose verb has since been refused**
    /// (`professional-ui`, HARD RULE 1).
    ///
    /// The companion to `every_disclosed_card_closes_from_the_control_that_opened_it`, and the half
    /// that guard could not see: it exercises `Disclosed::toggled` and never renders anything, so
    /// the send card shipped with no `Done` at all and every test stayed green.
    ///
    /// The third actor is the one that makes this more than a presence check. `Disclosed::Send`
    /// survives in egui's store, so an account sealing under an open form leaves the verb that
    /// opened it refused — and with no control inside the card, nothing on the tab can close it.
    ///
    /// `Disclosed::Nothing` is the control: without it, a pane that drew a `Done` unconditionally —
    /// on a resting tab with no card open — would pass every assertion above.
    #[test]
    fn every_disclosed_card_draws_a_way_out_even_when_its_verb_is_refused() {
        let sealed = TrayView {
            running: true,
            account: Some(AccountState::Locked),
            ..TrayView::default()
        };
        for (what, view, open) in [
            (
                "the receive card",
                sendable(SendProgress::Idle),
                Disclosed::Receive,
            ),
            (
                "the send card",
                sendable(SendProgress::Idle),
                Disclosed::Send,
            ),
            // The trap: the form is open and the verb that opened it now refuses.
            (
                "a sealed wallet's open send card",
                sealed.clone(),
                Disclosed::Send,
            ),
        ] {
            // Both widths: 480 is the shell's own minimum and the width at which `action::buttons`
            // wraps the verb row onto a second line, so it is where a control is likeliest to be
            // pushed somewhere it cannot be reached.
            for width in [480.0, 900.0] {
                let said = painted_pane_with(&view, width, open);
                assert!(
                    said.iter()
                        .any(|line| line.contains(copy::wallet::CLOSE_BUTTON)),
                    "at {width} px {what} drew no way out, so a reader who scrolled past the verb \
                     row is stuck with it: {said:?}"
                );
            }
        }

        let resting = painted_pane_with(&sendable(SendProgress::Idle), 900.0, Disclosed::Nothing);
        assert!(
            !resting
                .iter()
                .any(|line| line.contains(copy::wallet::CLOSE_BUTTON)),
            "a tab with nothing open drew a close control, so the assertions above cannot tell a \
             disclosed card's escape from one drawn unconditionally: {resting:?}"
        );
    }

    /// **A payment in flight is NOT dismissible — including on the path a person actually takes.**
    ///
    /// The other side of the escape rule. A card on screen because money is moving must not offer
    /// to hide it, and a `Done` that visibly failed to close anything is the same defect wearing a
    /// working-looking control.
    ///
    /// **BOTH disclosure states, and the second one is the whole point.** An earlier version of
    /// this test forced `Disclosed::Nothing`, which only covers a card drawn *solely* because a
    /// payment is in flight — a state nobody reaches by sending. The ORDINARY path is: open the
    /// form, send from it. Nothing on the send path clears the disclosure, so `Disclosed::Send` is
    /// still set for the whole flight, and the version that gated on `disclosed` alone drew a
    /// `Done` there that closed nothing visible. The security gate found that; this actor is what
    /// would have caught it.
    #[test]
    fn a_payment_in_flight_offers_no_control_to_hide_it() {
        for send in every_send_state() {
            if matches!(send, SendProgress::Idle) {
                continue;
            }
            for open in [Disclosed::Nothing, Disclosed::Send] {
                let said = painted_pane_with(&sendable(send.clone()), 900.0, open);
                assert!(
                    said.iter()
                        .any(|line| line.contains(copy::wallet::SENDING_CARD)),
                    "{send:?} at {open:?} did not draw its card at all, so this proves nothing: \
                     {said:?}"
                );
                assert!(
                    !said
                        .iter()
                        .any(|line| line.contains(copy::wallet::CLOSE_BUTTON)),
                    "{send:?} at {open:?} offered a control to hide money in motion — or, with the \
                     card open, one that would clear the disclosure and visibly close nothing: \
                     {said:?}"
                );
            }
        }
    }

    /// **A refused verb says WHY, and the two verbs never wear each other's reason.**
    ///
    /// The never-trap rule applied to the verb row: a greyed control whose condition is unstated
    /// sends a person looking for it. Both refusals are drawn under the row, so they must be
    /// distinguishable — a locked account cannot send AND cannot show an address, and telling
    /// somebody "unlock to send" when the missing thing is the address names the wrong remedy.
    ///
    /// The unlocked, funded actor is the control: without it a pair of functions that refused
    /// unconditionally would satisfy every assertion above.
    #[test]
    fn a_refused_verb_states_its_own_condition_and_a_working_one_states_nothing() {
        let sealed = facts_with(TrayView {
            running: true,
            account: Some(AccountState::Locked),
            ..TrayView::default()
        });
        let send = send_refusal(&sealed).expect("a locked account cannot send");
        let receive = receive_refusal(&sealed).expect("a locked account has no address to show");
        assert!(!send.trim().is_empty() && !receive.trim().is_empty());
        assert_ne!(
            send, receive,
            "the two refused verbs wear one sentence, so the row names the wrong remedy for one \
             of them"
        );

        // Both sentences are captioned under the row as an unlabelled pair, so each has to name its
        // OWN subject to be readable — the reader has nothing else tying a sentence to a control.
        // That holds today by luck rather than by rule: these sentences were written for other
        // surfaces, where a label supplied the subject. Asserted so a future reword that drops the
        // subject reddens here instead of shipping two sentences under two buttons with no way to
        // tell which is which.
        assert!(
            send.contains(copy::wallet::SEND_BUTTON_OPEN),
            "the Send refusal never names Send, so under an unlabelled caption it could be read as \
             belonging to Receive: {send:?}"
        );
        assert!(
            receive.contains("address"),
            "the Receive refusal never names the address, so under an unlabelled caption it could \
             be read as belonging to Send: {receive:?}"
        );

        let working = facts_with(sendable(SendProgress::Idle));
        assert_eq!(send_refusal(&working), None, "a funded wallet refused Send");
        assert_eq!(
            receive_refusal(&working),
            None,
            "a wallet holding an address refused Receive"
        );
    }

    /// **A payment in flight draws its card without anybody opening it** (dig_ecosystem#2967).
    ///
    /// The one place the disclosure must not be obeyed. A settling payment is the newest thing on
    /// the tab, and putting it behind a control means a person who closed the send card — or who
    /// returned to the app after it was closed — sees a wallet reporting nothing about the money
    /// that is currently moving.
    ///
    /// Asserted over every non-`Idle` state, with `Idle` as the control: without that half, a card
    /// drawn unconditionally would pass, and the code would once again be permanent furniture.
    #[test]
    fn a_payment_in_flight_is_drawn_whether_or_not_its_card_was_opened() {
        for send in every_send_state() {
            let said = painted_pane_with(&sendable(send.clone()), 900.0, Disclosed::Nothing);
            let drawn = said
                .iter()
                .any(|line| line.contains(copy::wallet::SENDING_CARD));
            assert_eq!(
                drawn,
                !matches!(send, SendProgress::Idle),
                "with the card closed, {send:?} drew the sending card = {drawn}: a payment in \
                 flight must appear on its own, and an idle wallet must not"
            );
        }
    }

    /// An unlocked, funded view, so the send form is drawn in the state a person actually uses it in.
    fn sendable(send: SendProgress) -> TrayView {
        TrayView {
            running: true,
            node_connected: true,
            account: Some(AccountState::Unlocked { recoverable: true }),
            receive_address: Some(ADDRESS.to_string()),
            balance: BalanceReading::Known {
                balances: Balances {
                    xch_mojos: 1_000_000_000_000,
                    dig_units: 0,
                },
                as_of: crate::wallet::engine::BalanceAsOf::Replica {
                    height: 7_000_000,
                    caught_up: true,
                },
            },
            send,
            ..TrayView::default()
        }
    }

    /// Every state a send can be in, as the pane must be able to draw them.
    ///
    /// Hand-written because two variants carry strings, and checked against the enum by
    /// [`every_send_state_lists_every_arm`] so it cannot quietly shrink.
    fn every_send_state() -> Vec<SendProgress> {
        vec![
            SendProgress::Idle,
            SendProgress::Signing,
            SendProgress::Pending {
                payment_coin_id: "c0ffee".to_string(),
                blocks_since_push: 3,
            },
            SendProgress::Unknown {
                payment_coin_id: "decaf0".to_string(),
                detail: "the node did not answer".to_string(),
            },
            SendProgress::Confirmed {
                payment_coin_id: "5e771ed".to_string(),
                confirmed_height: 9_146_483,
            },
            SendProgress::Failed {
                reason: "the network rejected the transfer: DOUBLE_SPEND".to_string(),
                payment_coin_id: None,
            },
            SendProgress::Failed {
                reason: "a source coin was spent elsewhere".to_string(),
                payment_coin_id: Some("5e771ed".to_string()),
            },
            SendProgress::Abandoned {
                detail: "this app stopped part-way through the payment".to_string(),
            },
        ]
    }

    /// **The state list these guards run over is the whole enum.**
    #[test]
    fn every_send_state_lists_every_arm() {
        fn arm(send: &SendProgress) -> u8 {
            match send {
                SendProgress::Idle => 0,
                SendProgress::Signing => 1,
                SendProgress::Pending { .. } => 2,
                SendProgress::Unknown { .. } => 3,
                SendProgress::Confirmed { .. } => 4,
                SendProgress::Failed { .. } => 5,
                SendProgress::Abandoned { .. } => 6,
            }
        }
        let mut arms: Vec<u8> = every_send_state().iter().map(arm).collect();
        arms.sort_unstable();
        arms.dedup();
        assert_eq!(arms, (0..7).collect::<Vec<u8>>());
    }

    /// **Each send state is drawn as ITSELF, and an unknown outcome is never drawn as a failure**
    /// (dig_ecosystem#2819).
    ///
    /// The badge word is what a person takes at a glance, so every state must own one. The pair that
    /// matters is `Unknown` against `Failed`: the bundle behind an unknown may be in a mempool right
    /// now, and a screen calling that "Not sent" invites the one action that can pay twice. Asserted
    /// as *this word present AND every other state's word absent*, because a card that printed all
    /// six badges would satisfy a presence-only check.
    #[test]
    fn each_send_state_is_drawn_as_itself_and_an_unknown_outcome_is_not_a_failure() {
        let words = [
            (1_usize, copy::wallet::SEND_SIGNING_BADGE),
            (2, copy::wallet::SEND_PENDING_BADGE),
            (3, copy::wallet::SEND_UNKNOWN_BADGE),
            (4, copy::wallet::SEND_CONFIRMED_BADGE),
            (5, copy::wallet::SEND_FAILED_BADGE),
        ];
        for (index, word) in words {
            let said = painted_pane(&sendable(every_send_state()[index].clone()), 900.0);
            assert!(
                said.iter().any(|line| line.contains(word)),
                "{:?} never drew its own badge: {said:?}",
                every_send_state()[index]
            );
            for (other, sibling) in words {
                assert!(
                    other == index || !said.iter().any(|line| line.contains(sibling)),
                    "{:?} was also drawn as {sibling:?}",
                    every_send_state()[index]
                );
            }
        }

        // Idle draws none of them: a wallet that has sent nothing must not report an outcome.
        let idle = painted_pane(&sendable(SendProgress::Idle), 900.0);
        for (_, word) in words {
            assert!(
                !idle.iter().any(|line| line.contains(word)),
                "a wallet that has sent nothing reported {word:?}: {idle:?}"
            );
        }
    }

    /// **A pending send shows how long it has been waiting, and only a confirmation says it
    /// arrived.**
    ///
    /// The money-lie guard for this card. `Awaiting` is the ordinary answer for several blocks, and a
    /// surface that greeted it with the settled word would tell a person their payment is final while
    /// it is still reversible by a reorg.
    #[test]
    fn a_pending_send_never_reads_as_arrived_and_says_how_far_along_it_is() {
        let pending = painted_pane(
            &sendable(SendProgress::Pending {
                payment_coin_id: "c0ffee".to_string(),
                blocks_since_push: 3,
            }),
            900.0,
        );
        assert!(
            !pending
                .iter()
                .any(|line| line.contains(copy::wallet::SEND_CONFIRMED_BADGE)),
            "a payment still settling was drawn as arrived: {pending:?}"
        );
        assert!(
            pending.iter().any(|line| line.contains("3 block")),
            "the wait was drawn without saying how long it has been: {pending:?}"
        );
        assert!(
            pending.iter().any(|line| line.contains("c0ffee")),
            "the payment coin a person can look up was not shown: {pending:?}"
        );
    }

    /// **The fee is drawn through the shared formatter, never as its raw mojo count**
    /// (dig_ecosystem#2295, dig_ecosystem#2885).
    ///
    /// `DEFAULT_SEND_FEE_MOJOS` is 1,000,000 mojos, which is 0.000001 XCH. A card that printed the
    /// base-unit figure beside `XCH` would overstate the cost by a factor of 10^12 — the defect that
    /// shipped in the custody dialog, on the surface where a person decides what to pay. Both halves
    /// are asserted: the correct figure present, and the raw count absent.
    #[test]
    fn the_fee_is_shown_in_xch_and_never_as_a_raw_mojo_count() {
        let said = painted_pane_with(&sendable(SendProgress::Idle), 900.0, Disclosed::Send);
        let fee = format_amount(Asset::Xch, DEFAULT_SEND_FEE_MOJOS);
        assert_eq!(fee, "0.000001", "the fixture no longer pins a real fee");
        assert!(
            said.iter().any(|line| line.contains(&fee)),
            "the card never states what sending costs: {said:?}"
        );
        assert!(
            !said
                .iter()
                .any(|line| line.contains(&DEFAULT_SEND_FEE_MOJOS.to_string())),
            "the fee was drawn as its raw mojo count, which overstates it a trillion times: {said:?}"
        );
    }

    /// **A refused Send says WHY, in every state that refuses it** (`professional-ui`, never trap).
    ///
    /// Three actors that differ only in the reason: a sealed account, a send already running, and an
    /// empty form. A greyed control whose condition is unstated sends a person looking for it, so the
    /// sentence is drawn beneath it — and the sentences must differ, or three situations wear one
    /// answer.
    #[test]
    fn a_refused_send_states_the_condition_that_would_lift_it() {
        let sealed = SendDraft {
            destination: "",
            amount: "",
            account_open: false,
            balance: &BalanceReading::Pending,
            progress: &SendProgress::Idle,
        }
        .assess()
        .expect_err("a sealed account cannot send");
        let sealed_said = painted_pane(
            &TrayView {
                running: true,
                account: Some(AccountState::Locked),
                ..TrayView::default()
            },
            900.0,
        );
        assert!(
            sealed_said
                .iter()
                .any(|line| line.contains(&sealed.sentence())),
            "a locked wallet drew a Send it will not honour, with no reason: {sealed_said:?}"
        );

        let running = painted_pane(&sendable(SendProgress::Signing), 900.0);
        let already = SendBlocked::AlreadySending.sentence();
        assert!(
            running.iter().any(|line| line.contains(&already)),
            "a second send was offered mid-payment with nothing said about it: {running:?}"
        );
        assert_ne!(
            sealed.sentence(),
            already,
            "two different refusals wear one sentence"
        );
    }

    /// **A press on Send returns the transfer that was typed, and nothing else does.**
    ///
    /// The pane's whole contract with the shell: it returns an INTENT, already validated, and the
    /// shell only forwards it. Asserted through `assess` rather than a synthetic click because the
    /// value returned is the thing under test — that it carries the typed amount and the fixed fee,
    /// and that it exists only when the draft is sendable.
    #[test]
    fn the_pane_returns_a_validated_transfer_and_only_when_one_is_sendable() {
        let balance = BalanceReading::Known {
            balances: Balances {
                xch_mojos: 1_000_000_000_000,
                dig_units: 0,
            },
            as_of: crate::wallet::engine::BalanceAsOf::Replica {
                height: 7_000_000,
                caught_up: true,
            },
        };
        let draft = SendDraft {
            destination: ADDRESS,
            amount: "0.5",
            account_open: true,
            balance: &balance,
            progress: &SendProgress::Idle,
        };
        let request = draft.assess().expect("a funded, well-formed draft");
        assert_eq!(
            TrayAction::SendXch(request),
            TrayAction::SendXch(
                dig_account::TransferRequest::to_address(ADDRESS, 500_000_000_000)
                    .expect("a mainnet address")
                    .with_fee(DEFAULT_SEND_FEE_MOJOS)
            ),
            "the action carried something other than the amount and fee the card showed"
        );
    }

    /// **The pane offers exactly the verbs the model put on the tab.**
    ///
    /// Asserted against the real `window_model::build` output rather than a fixture, so a change to
    /// the Wallet tab upstream is reflected without editing this test — and a pane that filtered a
    /// verb out, or invented one, fails.
    #[test]
    fn the_pane_offers_the_models_verbs_and_nothing_else() {
        let view = TrayView {
            running: true,
            account: Some(AccountState::Unlocked { recoverable: true }),
            receive_address: Some(ADDRESS.to_string()),
            ..TrayView::default()
        };
        let model = crate::window_model::build(&view);
        let tab = model
            .tabs
            .iter()
            .find(|tab| tab.id == crate::window_model::TabId::Wallet)
            .expect("the Wallet tab exists for an unlocked account");

        let expected: Vec<(String, bool)> = tab
            .sections
            .iter()
            .flat_map(|section| section.rows.iter())
            .filter_map(|row| match row {
                MenuRow::Action { label, enabled, .. } => Some((label.clone(), *enabled)),
                _ => None,
            })
            .collect();
        let drawn: Vec<(String, bool)> = super::super::actions_of(tab)
            .into_iter()
            .map(|action| (action.label, action.enabled))
            .collect();
        assert_eq!(drawn, expected);
        assert!(
            !drawn.is_empty(),
            "the fixture produced no verbs, so this test could not tell a filter from an empty tab"
        );
    }

    /// **A disabled first verb leaves the group without a primary, and none of them is danger.**
    ///
    /// The Wallet tab's one row is disabled precisely when the account is sealed, which is the case
    /// that would otherwise promote whatever verb happens to be pressable into the page's most
    /// prominent control.
    #[test]
    fn a_sealed_account_promotes_nothing_and_endangers_nothing() {
        let view = TrayView {
            running: true,
            account: Some(AccountState::Locked),
            ..TrayView::default()
        };
        let model = crate::window_model::build(&view);
        let tab = model
            .tabs
            .iter()
            .find(|tab| tab.id == crate::window_model::TabId::Wallet)
            .expect("the Wallet tab exists for a locked account");
        let drawn = super::super::actions_of(tab);
        assert!(
            drawn.iter().any(|action| !action.enabled),
            "the fixture has no disabled verb, so it cannot see a wrongly-promoted one"
        );
        assert!(drawn.iter().all(|action| action.weight != Weight::Danger));
        assert!(drawn
            .iter()
            .all(|action| action.weight != Weight::Primary || action.enabled));
    }
}
