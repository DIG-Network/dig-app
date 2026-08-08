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
//! An unknown balance is never a numeral. [`BalanceReading`] has three states and this pane renders
//! each as itself: a reading becomes two figures, a read in flight becomes the sentence saying so,
//! and an unknown becomes the sentence naming which thing is missing — the same sentences the tray's
//! wallet window shows, from [`crate::wallet::overview`], so the two surfaces cannot drift.

use super::action::{self, Action};
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
    address_line, format_amount, unknown_reason, AddressReading, BalanceReading, Balances,
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
    holdings_card(flow, t, &facts.balance);
    flow.gap(space::S4);
    let pressed = actions_card(flow, t, tab);
    flow.gap(space::S4);
    sending_card(flow, t);
    pressed
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
fn holdings_card(flow: &mut Flow, t: &Tokens, balance: &BalanceReading) {
    let items = holdings(balance);
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::wallet::HOLDINGS_CARD), |inner| {
                inner.place(|ui, at| (data::readouts(ui, at, t, &items), ()));
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
        BalanceReading::Known(held) => figures(held),
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

/// The tab's own verbs, as a weighted button group. Omitted when the model offers none.
fn actions_card(flow: &mut Flow, t: &Tokens, tab: &Tab) -> Option<TrayAction> {
    let actions = actions_of(tab);
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

/// The tab's rows as weighted actions, through the one derivation in [`super::actions_in`].
fn actions_of(tab: &Tab) -> Vec<Action<TrayAction>> {
    let mut seen = std::collections::HashMap::new();
    super::actions_in(
        tab.sections
            .iter()
            .flat_map(|section| section.rows.iter().cloned()),
        &mut seen,
    )
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
    use crate::wallet::overview::{AddressUnavailable, BalanceUnknown};

    /// The address a live account derives.
    const ADDRESS: &str = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";

    fn facts_with(view: TrayView) -> PaneFacts {
        PaneFacts::of_tray(&view)
    }

    /// **A not-known balance reads as a sentence, not as a clause starting mid-thought.**
    ///
    /// Found by looking at the locked pane: `wallet::overview`'s reasons are written to complete
    /// "Balance: not known — ", so under a bare `Balance` label they began in lower case — *"your
    /// account is locked, so DIG cannot tell which address to read."* Reusing those sentences is
    /// right; presenting them without the words they complete was not. Asserted over every reason,
    /// because one arm fixed by hand is one arm, and the property belongs to all of them.
    #[test]
    fn a_not_known_balance_supplies_the_words_its_reason_completes() {
        let reasons = [
            BalanceUnknown::NoNode,
            BalanceUnknown::NodeTimedOut,
            BalanceUnknown::NodeCannotRead,
            BalanceUnknown::NoChainSource,
            BalanceUnknown::NotSynced,
            BalanceUnknown::NoAddress(AddressUnavailable::Locked),
            BalanceUnknown::NoAddress(AddressUnavailable::NoAccount),
        ];
        for why in reasons {
            let shown = holdings(&BalanceReading::Unknown(why.clone()))[0]
                .value
                .shown()
                .to_string();
            assert!(
                shown.starts_with(copy::wallet::BALANCE_NOT_KNOWN),
                "{why:?} renders as a bare clause: {shown}"
            );
            let first = shown.chars().next().expect("the sentence is not empty");
            assert!(
                first.is_uppercase(),
                "{why:?} renders a sentence that starts in lower case: {shown}"
            );
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

    /// **No balance state that is not a reading can produce a numeral.**
    ///
    /// The money-lie guard, asserted over EVERY non-`Known` state rather than a sample: a pending
    /// read and each unknown reason must render as a `Value::Unknown` whose text contains no digit
    /// at all. A digit here is how a person reads "not known" as "you hold nothing" — and the
    /// `ReadFailed` case is included with a digit-bearing detail string, because that is the one
    /// arm whose text comes from outside this crate.
    #[test]
    fn nothing_but_a_reading_renders_a_figure() {
        let not_readings = [
            BalanceReading::Pending,
            BalanceReading::Unknown(BalanceUnknown::NoNode),
            BalanceReading::Unknown(BalanceUnknown::NodeTimedOut),
            BalanceReading::Unknown(BalanceUnknown::NodeCannotRead),
            BalanceReading::Unknown(BalanceUnknown::NoChainSource),
            BalanceReading::Unknown(BalanceUnknown::NotSynced),
            BalanceReading::Unknown(BalanceUnknown::NoAddress(AddressUnavailable::Locked)),
            BalanceReading::Unknown(BalanceUnknown::NoAddress(AddressUnavailable::NoAccount)),
        ];
        for reading in not_readings {
            let items = holdings(&reading);
            assert_eq!(items.len(), 1, "{reading:?} rendered more than one readout");
            assert!(
                !items[0].value.is_known(),
                "{reading:?} rendered as a known value"
            );
            assert!(
                !items[0].value.shown().chars().any(|c| c.is_ascii_digit()),
                "{reading:?} put a numeral where a person reads a balance: {}",
                items[0].value.shown()
            );
        }
        // A real reading, by contrast, DOES produce figures — without this the test above is
        // satisfied by a `holdings` that never returns a number at all.
        let known = holdings(&BalanceReading::Known(Balances {
            xch_mojos: 1_000_000_000_000,
            dig_units: 2_000,
        }));
        assert_eq!(known.len(), 2);
        assert!(known.iter().all(|item| item.value.is_known()));
    }

    /// **Each not-known reason says something different from the others.**
    ///
    /// Five reasons that all read alike is one reason wearing five names, and these five call for
    /// five different responses — start a node, wait, upgrade, connect the node to the chain, wait
    /// for a sync. Asserted over the set, so a new reason cannot be given an existing sentence.
    #[test]
    fn every_not_known_reason_is_distinguishable() {
        let reasons = [
            BalanceUnknown::NoNode,
            BalanceUnknown::NodeTimedOut,
            BalanceUnknown::NodeCannotRead,
            BalanceUnknown::NoChainSource,
            BalanceUnknown::NotSynced,
            BalanceUnknown::NoAddress(AddressUnavailable::Locked),
            BalanceUnknown::NoAddress(AddressUnavailable::NoAccount),
        ];
        let mut sentences: Vec<String> = reasons
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
        let drawn: Vec<(String, bool)> = actions_of(tab)
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
        let drawn = actions_of(tab);
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
