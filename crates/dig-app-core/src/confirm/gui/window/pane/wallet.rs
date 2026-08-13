//! The Wallet tab: where money arrives, what is held, and what this wallet still cannot do.
//!
//! # Why receiving leads
//!
//! Receiving is the only thing this wallet does today, and the address is the only value on the tab a
//! person takes to another device. So the address and its code are the first card, the balances sit
//! under them, and the card that reserves sending's place is last — a page ordered by what a person
//! can actually do, rather than by what a wallet usually looks like.
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

use super::action;
use super::card;
use super::copy;
use super::data::{self, Readout, Tone, Value};
use super::facts::PaneFacts;
use super::flow::Flow;
use super::identity;
use super::text;
use crate::confirm::gui::render::space;
use crate::confirm::gui::theme::Tokens;
use crate::tray_menu::TrayAction;
use crate::wallet::overview::{
    address_line, as_of_sentence, format_amount, is_syncing, unknown_reason, AddressReading,
    BalanceReading, Balances,
};
use crate::wallet::state::Asset;
use crate::window_model::Tab;

/// Draw the Wallet pane's content into `flow`, and report the action pressed.
pub(crate) fn draw(
    flow: &mut Flow,
    t: &Tokens,
    tab: &Tab,
    facts: &PaneFacts,
) -> Option<TrayAction> {
    receive_card(flow, t, facts);
    flow.gap(space::S4);
    holdings_card(flow, t, &facts.balance, facts);
    flow.gap(space::S4);
    sending_card(flow, t);
    // The tab's own verbs, LAST and in a card of their own — but only where the model offers one
    // this pane has not already drawn. See [`spare_verbs`].
    spare_verbs_card(flow, t, tab, drew_copy_control(facts))
}

/// The address money arrives at: the code, the value, and the way to lift it off the screen.
///
/// # Why the card is drawn even with no address
///
/// Unlike the Status tab's receiving card — which is a demonstration and is simply omitted when there
/// is nothing to show — this is the Wallet tab's subject. A person who opens Wallet and finds no
/// mention of an address learns nothing; the reason they have none, and what changes it, is the most
/// useful thing on the page.
fn receive_card(flow: &mut Flow, t: &Tokens, facts: &PaneFacts) {
    let address = address_of(facts);
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::wallet::RECEIVE_CARD), |inner| {
                match &address {
                    AddressReading::Known(address) => known_address(inner, t, address),
                    // The sentence from `wallet::overview`, verbatim — one arm per account state,
                    // each naming the remedy that actually applies to it.
                    unavailable => {
                        let sentence = address_line(unavailable);
                        inner.place(|ui, at| {
                            (
                                data::readout(
                                    ui,
                                    at,
                                    t,
                                    &Readout::new(
                                        copy::wallet::ADDRESS_LABEL,
                                        Value::Unknown(sentence),
                                    ),
                                ),
                                (),
                            )
                        });
                    }
                }
            }),
            (),
        )
    });
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

/// What this account holds, or the reason there is no figure.
///
/// A shown figure is always followed by what it is true AS OF. A light client trails the chain tip
/// permanently, so the figure above is a statement about a moment rather than about now, and the
/// as-of line is what makes it a true one (dig_ecosystem#2824). It carries only its own provenance:
/// how far behind the node is, is the header strip's job, and repeating it here would say the same
/// thing twice in two voices.
fn holdings_card(flow: &mut Flow, t: &Tokens, balance: &BalanceReading, facts: &PaneFacts) {
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
            card::card(ui, at, t, Some(copy::wallet::HOLDINGS_CARD), |inner| {
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
                inner.place(|ui, at| (data::readouts(ui, at, t, &items), ()));
                if let Some(sentence) = &as_of {
                    inner.gap(space::S2);
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

/// The place sending will occupy (dig_ecosystem#2207), holding no control at all.
///
/// A card rather than silence: sending is the thing a person expects of a wallet, and a page that
/// does not mention it reads as one where the button is hidden somewhere. A card rather than a
/// disabled button, for the reason in [`copy::wallet::SENDING_BODY`] — a greyed **Send** sends
/// somebody looking for the condition that ungreys it.
fn sending_card(flow: &mut Flow, t: &Tokens) {
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::wallet::SENDING_CARD), |inner| {
                inner.place(|ui, at| {
                    (
                        data::badge(
                            ui,
                            at.left_top(),
                            t,
                            copy::wallet::SENDING_BADGE,
                            Tone::Neutral,
                        )
                        .height(),
                        (),
                    )
                });
                inner.gap(space::S3);
                inner.place(|ui, at| (text::body(ui, at, t, copy::wallet::SENDING_BODY), ()));
                inner.gap(space::S2);
                inner.place(|ui, at| (text::caption(ui, at, t, copy::wallet::SENDING_HINT), ()));
            }),
            (),
        )
    });
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
/// Derived from the same [`address_of`] the card itself renders from, so the two cannot come to
/// disagree about whether the control is on screen.
fn drew_copy_control(facts: &PaneFacts) -> bool {
    matches!(address_of(facts), AddressReading::Known(_))
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
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
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
            let said = painted_pane(&view, width);
            let times = said.iter().filter(|word| word.contains(ADDRESS)).count();
            assert_eq!(
                times, 1,
                "at {width} px the Wallet tab writes the address {times} times, not once: {said:?}"
            );
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

    /// **Copy-address is offered ONCE — beside the address, and only where that control exists.**
    ///
    /// dig_ecosystem#2357's wallet half, and the trap inside it. Two actors that differ only in
    /// whether the account is open:
    ///
    /// - an OPEN account draws the copy control next to the address, so the model's row must not be
    ///   drawn a second time in a card of its own;
    /// - a SEALED account draws no copy control at all, so the row is the only rendering there is
    ///   and removing it would take a verb the model offers off the screen entirely.
    ///
    /// A single-actor test — either one — passes on an unconditional filter, which is the wrong
    /// implementation nearest to this one, and which the pane-level reachability guard caught.
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
            drew_copy_control(&open) && !drew_copy_control(&sealed),
            "the fixtures do not differ in whether the receive card draws a copy control, so this \
             test cannot tell a conditional filter from an unconditional one"
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
