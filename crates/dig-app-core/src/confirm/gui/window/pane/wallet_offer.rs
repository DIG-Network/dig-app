//! The Wallet tab's OFFER card: paste an `offer1…` string, read what it actually is, take it
//! (dig_ecosystem#3077, slices O1 + O2).
//!
//! # Why the terms on screen cannot drift from the swap that settles
//!
//! Everything drawn here comes from a [`ReviewedOffer`], which owns the offer bytes and the summary
//! those very bytes produced and whose only constructor is the parser. The take path is handed the
//! SAME value through [`crate::wallet::offer::staged`] — no `offer1…` string travels separately — so
//! there is no window in which this card could describe one swap while another settles.
//!
//! # Why both sides are named, and no net figure is shown (NC-14)
//!
//! A take is irreversible on confirmation and its effect is a change of OWNERSHIP, not a movement in
//! a balance. So the card states what arrives and what leaves as two labelled lists. It deliberately
//! does not compute a difference: a single net number describes the same act as an arithmetic result
//! and hides half of what a person is agreeing to.
//!
//! This matters more than it might sound, because the custody ceremony downstream shows only the
//! side the taker PAYS — the received leg returns to the taker's own change address and is dropped
//! as change (measured in `wallet::take_reaches_the_custody_gate`). This card is therefore the only
//! surface on which both halves of the swap are ever visible, and it is where consent is really
//! given.
//!
//! # Why the progress this card draws is its OWN
//!
//! The centralized progress modal (dig_ecosystem#3075) observes [`crate::transaction::Feed`], and
//! the take path never publishes to it — so **no modal is raised for a take**. This card therefore
//! draws its own Working/Broadcast/Failed states rather than inheriting them.
//!
//! It reports only what it knows itself: a node accepted the bundle. Whether the swap settled is a
//! chain read that **nothing currently performs for a take**, and nothing here claims one. Both
//! gaps are dig_ecosystem#3111 — this card's honesty is a stopgap, not evidence they are covered.

use super::card;
use super::copy;
use super::data::{self, Readout, Tone, Value};
use super::field;
use super::flow::Flow;
use super::text;
use crate::amount::format_xch;
use crate::confirm::gui::paint;
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::tray_menu::TrayAction;
use crate::wallet::offer::{OfferError, OfferLeg, OfferTerms, ReviewedOffer};
use crate::wallet::taking::TakeProgress;

/// The id the pasted text is remembered under between frames.
fn element() -> egui::Id {
    egui::Id::new("dig-window-wallet-offer")
}

/// Draw the offer card and report the action pressed.
///
/// `account_open` is the account's own state, not a re-derived rule: taking needs a key, and a
/// locked account must say so on the control rather than at signing time.
pub(crate) fn card(flow: &mut Flow, t: &Tokens, account_open: bool) -> Option<TrayAction> {
    let live = flow.live();
    flow.place(|ui, at| {
        let pressed = card::interactive_card(ui, at, t, live, Some(copy::offer::CARD), |inner| {
            body(inner, t, account_open)
        });
        (pressed.0, pressed.1.flatten())
    })
}

/// The card's contents: whatever state the take is in, then the field, the terms and the control.
fn body(inner: &mut Flow, t: &Tokens, account_open: bool) -> Option<TrayAction> {
    let progress = crate::wallet::taking::progress();
    if !matches!(progress, TakeProgress::Idle) {
        outcome(inner, t, &progress);
        inner.gap(space::S4);
    }

    let typed = paste_field(inner, t);
    let reading = read(&typed);

    // Staged on EVERY frame, including as `None`, so the value the shell would take always matches
    // what this card is showing. Staging only on success would leave the last good offer armed after
    // a person had cleared or replaced the field.
    crate::wallet::offer::stage(reading.as_ref().ok().cloned());

    match &reading {
        Ok(reviewed) => {
            inner.gap(space::S4);
            terms(inner, t, reviewed.terms());
            inner.gap(space::S4);
            take_control(inner, t, reviewed.terms(), account_open, &progress)
        }
        Err(None) => {
            // The EMPTY state. A card that showed nothing here would teach a person the field does
            // nothing until it is filled; the sentence says what to put in it.
            inner.gap(space::S3);
            inner.place(|ui, at| (text::caption(ui, at, t, copy::offer::EMPTY_HINT), ()));
            None
        }
        Err(Some(why)) => {
            inner.gap(space::S3);
            inner.place(|ui, at| (text::body(ui, at, t, why), ()));
            None
        }
    }
}

/// Read the typed text, distinguishing *nothing typed yet* from *typed, and not an offer*.
///
/// `Err(None)` is the empty state and `Err(Some(_))` is the failure state — they are different
/// screens, and collapsing them would greet an untouched field with an error.
fn read(typed: &str) -> Result<ReviewedOffer, Option<String>> {
    if typed.trim().is_empty() {
        return Err(None);
    }
    ReviewedOffer::read(typed).map_err(|e| match e {
        OfferError::Unreadable(why) => Some(why),
        // Unreachable from a parse, and rendered rather than swallowed: a refusal a surface cannot
        // draw is a refusal a person never learns about.
        OfferError::CustodyForbids(why) => Some(why),
    })
}

/// The field an offer is pasted or scanned into, remembered across frames.
fn paste_field(flow: &mut Flow, t: &Tokens) -> String {
    let element = element();
    let live = flow.live();
    let mut typed: String = flow.place(|ui, _| {
        (
            0.0,
            ui.data(|d| d.get_temp(element.with("text")))
                .unwrap_or_default(),
        )
    });

    flow.place(|ui, at| {
        (
            field::text_field(
                ui,
                at,
                t,
                live,
                &field::Field {
                    label: copy::offer::PASTE_LABEL,
                    placeholder: copy::offer::PASTE_PLACEHOLDER,
                    help: copy::offer::PASTE_HINT,
                    error: None,
                    id: element.with("text"),
                },
                &mut typed,
            ),
            (),
        )
    });
    flow.place(|ui, _| {
        ui.data_mut(|d| d.insert_temp(element.with("text"), typed.clone()));
        (0.0, ())
    });
    typed
}

/// Both sides of the swap, each under its own heading, in the taker's own direction.
fn terms(flow: &mut Flow, t: &Tokens, terms: &OfferTerms) {
    side(flow, t, copy::offer::YOU_RECEIVE, &terms.you_receive);
    flow.gap(space::S3);
    side(flow, t, copy::offer::YOU_PAY, &terms.you_pay);

    if !terms.royalties.is_empty() {
        flow.gap(space::S3);
        let owed = royalty_sentence(&terms.royalties);
        flow.place(|ui, at| (text::caption(ui, at, t, &owed), ()));
    }
}

/// One side of the swap: its heading, then a readout per leg.
///
/// An EMPTY side is drawn as a stated absence rather than omitted. A one-sided offer is a real thing
/// a person can be handed, and a card that simply left the heading out would show it as though it
/// only had the side that was populated.
fn side(flow: &mut Flow, t: &Tokens, heading: &str, legs: &[OfferLeg]) {
    flow.place(|ui, at| (text::body(ui, at, t, heading), ()));
    flow.gap(space::S2);
    let items: Vec<Readout> = match legs.is_empty() {
        true => vec![Readout::new(
            copy::offer::NOTHING_LABEL,
            Value::Unknown(copy::offer::NOTHING_ON_THIS_SIDE.to_string()),
        )],
        false => legs.iter().map(readout_of).collect(),
    };
    flow.place(|ui, at| (data::readouts(ui, at, t, &items), ()));
}

/// One leg as a readout.
///
/// XCH goes through the one formatter that knows the asset has twelve decimal places; a CAT amount
/// is shown in its own base units and labelled by asset id, because this app has no name for an
/// arbitrary token and inventing one would be a claim about what the token IS.
fn readout_of(leg: &OfferLeg) -> Readout {
    match leg {
        OfferLeg::Xch { mojos } => {
            Readout::new(copy::offer::XCH_LABEL, Value::Word(format_xch(*mojos)))
        }
        OfferLeg::Cat { asset_id, amount } => Readout::new(
            copy::offer::cat_label(asset_id),
            Value::Word(amount.to_string()),
        ),
        OfferLeg::Nft { launcher_id } => Readout::new(
            copy::offer::NFT_LABEL,
            Value::Identifier(launcher_id.clone()),
        ),
    }
}

/// The royalties the offer carries, in one sentence.
fn royalty_sentence(royalties: &[(String, u16)]) -> String {
    let total: u32 = royalties.iter().map(|(_, bps)| u32::from(*bps)).sum();
    copy::offer::royalties(royalties.len(), f64::from(total) / 100.0)
}

/// The control that takes the offer, and — when it is refused — the reason under it.
///
/// `professional-ui`'s never-trap rule: a control that cannot be pressed states why, in the same
/// place the person is looking. Every refusal here is a real precondition rather than a guess, and
/// each is checked BEFORE a spend is built so nobody confirms a swap that was never permitted.
fn take_control(
    flow: &mut Flow,
    t: &Tokens,
    terms: &OfferTerms,
    account_open: bool,
    progress: &TakeProgress,
) -> Option<TrayAction> {
    let refusal = refusal_for(terms, account_open, progress);
    let live = flow.live();
    let pressed = flow.place(|ui, at| {
        let hit = paint::button_at(
            ui,
            egui::Rect::from_min_size(
                at.left_top(),
                egui::Vec2::new(
                    paint::button_width(ui, copy::offer::TAKE_BUTTON),
                    paint::BUTTON_HEIGHT,
                ),
            ),
            element().with("take"),
            copy::offer::TAKE_BUTTON,
            match refusal.is_none() {
                true => Weight::Primary,
                false => Weight::Ghost,
            },
            refusal.is_none() && live,
            t,
        )
        .clicked();
        (paint::BUTTON_HEIGHT, hit)
    });

    if let Some(why) = &refusal {
        flow.gap(space::S2);
        flow.place(|ui, at| (text::caption(ui, at, t, why), ()));
    }

    match pressed && refusal.is_none() {
        true => Some(TrayAction::TakeOffer),
        false => None,
    }
}

/// Why the take control is refused, or `None` when it may be pressed.
///
/// Ordered by what a person can act on soonest. Custody comes first because it is a property of the
/// profile that no amount of unlocking or waiting changes.
fn refusal_for(terms: &OfferTerms, account_open: bool, progress: &TakeProgress) -> Option<String> {
    if terms.is_empty() {
        return Some(copy::offer::REFUSED_EMPTY.to_string());
    }
    if !account_open {
        return Some(copy::offer::REFUSED_LOCKED.to_string());
    }
    if matches!(progress, TakeProgress::Working) {
        return Some(copy::offer::REFUSED_IN_FLIGHT.to_string());
    }
    None
}

/// What became of the take in flight, drawn as the state it actually is.
///
/// [`TakeProgress::Broadcast`] gets its own words and NOT a success badge, because reaching it means
/// a node accepted a bundle. Whether the swap settled is a chain read this card never performs, and a
/// green "done" here would be the money lie the wallet refuses everywhere else.
fn outcome(flow: &mut Flow, t: &Tokens, progress: &TakeProgress) {
    let (word, tone, body) = match progress {
        TakeProgress::Idle => return,
        TakeProgress::Working => (
            copy::offer::WORKING_BADGE,
            Tone::Neutral,
            copy::offer::WORKING_BODY.to_string(),
        ),
        TakeProgress::Broadcast { bundle_name } => (
            copy::offer::BROADCAST_BADGE,
            Tone::Neutral,
            copy::offer::broadcast_body(bundle_name),
        ),
        TakeProgress::Failed { why } => (
            copy::offer::FAILED_BADGE,
            Tone::Warn,
            copy::offer::failed_body(why),
        ),
    };

    flow.place(|ui, at| (data::badge(ui, at.left_top(), t, word, tone).height(), ()));
    flow.gap(space::S3);
    flow.place(|ui, at| (text::body(ui, at, t, &body), ()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::offer_fixture::{an_offer_of, XCH_FOR_XCH};

    fn reviewed() -> ReviewedOffer {
        ReviewedOffer::read(&an_offer_of(XCH_FOR_XCH)).expect("the fixture offer reads")
    }

    /// **An untouched field is the EMPTY state, and typed nonsense is the FAILURE state.**
    ///
    /// The two render differently and must be told apart at the source, because a reader that
    /// collapsed them would greet a person who has typed nothing with a parse error.
    #[test]
    fn nothing_typed_is_not_the_same_as_something_unreadable() {
        assert!(matches!(read("   "), Err(None)));
        assert!(matches!(read("not an offer"), Err(Some(_))));
        assert!(read(reviewed().offer()).is_ok());
    }

    /// **Every refusal state is reachable and distinguishable, and a takeable offer is refused by
    /// nothing.**
    ///
    /// Each case varies exactly ONE precondition away from the takeable control, so a rule that
    /// refused everything and a rule that refused nothing both fail — which a single hostile fixture
    /// could not see.
    #[test]
    fn each_refusal_names_its_own_precondition_and_a_takeable_offer_names_none() {
        let terms = reviewed().terms().clone();
        let empty = OfferTerms {
            you_receive: Vec::new(),
            you_pay: Vec::new(),
            royalties: Vec::new(),
        };

        assert_eq!(refusal_for(&terms, true, &TakeProgress::Idle), None);

        let locked =
            refusal_for(&terms, false, &TakeProgress::Idle).expect("a locked account cannot take");
        let in_flight = refusal_for(&terms, true, &TakeProgress::Working)
            .expect("a second take is refused while one is in flight");
        let nothing = refusal_for(&empty, true, &TakeProgress::Idle)
            .expect("an offer with no named sides is not takeable");

        assert_ne!(locked, in_flight);
        assert_ne!(locked, nothing);
        assert_ne!(in_flight, nothing);
    }

    /// **The two sides are labelled from the taker's point of view and carry different figures.**
    ///
    /// The fixture's sides differ (400 offered, 1,000 requested), so a readout builder that read the
    /// wrong side produces the wrong figure rather than an identical one.
    #[test]
    fn each_leg_is_shown_in_the_asset_its_own_formatter_knows() {
        let terms = reviewed().terms().clone();

        let receive = readout_of(&terms.you_receive[0]);
        let pay = readout_of(&terms.you_pay[0]);

        assert_eq!(receive.value, Value::Word(format_xch(400)));
        assert_eq!(pay.value, Value::Word(format_xch(1_000)));
        assert_ne!(
            receive.value, pay.value,
            "the two sides must not render identically"
        );
    }

    /// **A broadcast take is never drawn as a settled one.**
    ///
    /// The words are asserted rather than the badge alone, because a `Good` tone with honest words is
    /// still the claim a person reads.
    #[test]
    fn a_broadcast_take_does_not_claim_the_swap_completed() {
        let body = copy::offer::broadcast_body("abc123");
        assert!(
            body.contains("accepted") && !body.to_lowercase().contains("complete"),
            "a broadcast is an acceptance, not a completed swap: {body}"
        );
    }
}
