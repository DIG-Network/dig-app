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
use super::offer_file;
use super::text;
use crate::amount::format_xch;
use crate::confirm::gui::paint;
use crate::confirm::gui::render::{radius, rgba, space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::tray_menu::TrayAction;
use crate::wallet::cancelling::CancelProgress;
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
///
/// A file let go over the card is applied BEFORE the card is drawn, so the offer it carries is read,
/// summarised and confirmed by the very code a paste goes through — this frame, not the next one.
pub(crate) fn card(flow: &mut Flow, t: &Tokens, account_open: bool) -> Option<TrayAction> {
    let live = flow.live();
    flow.place(|ui, at| {
        let region = region(ui, at);
        if let Some(files) = dropped_onto(ui, region) {
            apply(ui, &files);
        }
        let carrying = files_over(ui, region);

        let pressed = card::interactive_card(ui, at, t, live, Some(copy::offer::CARD), |inner| {
            body(inner, t, account_open, carrying)
        });
        remember_region(ui, pressed.0);
        if carrying {
            halo(ui, region_of(at, pressed.0), t);
        }
        (pressed.0, pressed.1.flatten())
    })
}

/// The rectangle a drop this frame is tested against: where the card was drawn LAST frame.
///
/// A card's height is whatever its content came to, and is therefore not known until after it is
/// laid out — but the drop-active state has to be visible while the file is still in the air, which
/// is before that. The previous frame's height is the only measurement that exists in time to be
/// used, and it is exact from the second frame on, since a card that is not changing size is
/// reporting the same number every frame.
///
/// The first frame falls back to the card's own minimum, so a drop on a card nobody has looked at
/// yet still lands somewhere honest rather than claiming the whole column.
fn region(ui: &egui::Ui, at: egui::Rect) -> egui::Rect {
    let height = ui
        .data(|d| d.get_temp::<f32>(element().with("height")))
        .unwrap_or(FIRST_FRAME_HEIGHT);
    region_of(at, height)
}

/// The card's rectangle, given the column it was placed in and the height it came to.
fn region_of(at: egui::Rect, height: f32) -> egui::Rect {
    egui::Rect::from_min_size(at.left_top(), egui::Vec2::new(at.width(), height))
}

/// Remember the height the card came to, for the next frame's drop test.
fn remember_region(ui: &egui::Ui, height: f32) {
    ui.data_mut(|d| d.insert_temp(element().with("height"), height));
}

/// The height a drop is tested against before the card has ever been measured.
///
/// A conservative guess: roughly a title, a field and its hint. Under-reaching costs one missed drop
/// on the very first frame; over-reaching would let this card claim a file meant for the card below
/// it, which is a wrong action rather than a missing one.
const FIRST_FRAME_HEIGHT: f32 = 160.0;

/// The files let go over `region` this frame, if any.
///
/// Routed by where the pointer IS, not by the card being on screen: the pane holds several cards and
/// a drop meant for another one must not be answered here.
fn dropped_onto(ui: &egui::Ui, region: egui::Rect) -> Option<Vec<egui::DroppedFile>> {
    ui.ctx().input(
        |i| match i.raw.dropped_files.is_empty() || !pointer_within(i, region) {
            true => None,
            false => Some(i.raw.dropped_files.clone()),
        },
    )
}

/// Whether files are being dragged over `region` right now.
fn files_over(ui: &egui::Ui, region: egui::Rect) -> bool {
    ui.ctx()
        .input(|i| !i.raw.hovered_files.is_empty() && pointer_within(i, region))
}

/// Whether the pointer is inside `region`, by whichever of its two positions the backend has.
fn pointer_within(i: &egui::InputState, region: egui::Rect) -> bool {
    i.pointer
        .hover_pos()
        .or_else(|| i.pointer.interact_pos())
        .is_some_and(|at| region.contains(at))
}

/// Load what was dropped into the field, or remember why it could not be.
///
/// On success the field is filled and nothing else happens: the loaded text is read on this same
/// frame by the code a paste goes through, so a drop cannot reach a swap that a paste could not.
/// Taking still needs the Take control to be pressed.
fn apply(ui: &egui::Ui, files: &[egui::DroppedFile]) {
    let element = element();
    match offer_file::from_drop(files) {
        Ok(text) => ui.data_mut(|d| {
            d.insert_temp(element.with("text"), text);
            d.remove_temp::<String>(element.with("problem"));
        }),
        Err(why) => ui.data_mut(|d| d.insert_temp(element.with("problem"), why)),
    }
}

/// How thick the drop-active outline is: enough to read as deliberate beside the card's own
/// hairline border, without redrawing the card as a different shape.
const HALO_WIDTH: f32 = 2.0;

/// The accent outline drawn around the card while a file is over it.
///
/// Drawn as well as said, because the sentence in the card explains what a drop DOES while the
/// outline says where it will land — and at 480 px the card below is close enough that "where" is
/// the part a person needs.
fn halo(ui: &egui::Ui, region: egui::Rect, t: &Tokens) {
    ui.painter().rect_stroke(
        region,
        radius::BASE,
        egui::Stroke::new(HALO_WIDTH, rgba(t.dig_purple)),
        egui::StrokeKind::Inside,
    );
}

/// The card's contents: whatever state the take is in, then the field, the terms and the control.
///
/// `carrying` is whether a file is in the air over this card right now, which changes what the field
/// says about itself and nothing else.
fn body(inner: &mut Flow, t: &Tokens, account_open: bool, carrying: bool) -> Option<TrayAction> {
    let progress = crate::wallet::taking::progress();
    if !matches!(progress, TakeProgress::Idle) {
        outcome(inner, t, &progress);
        inner.gap(space::S4);
    }

    let typed = paste_field(inner, t, carrying);
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
            let took = take_control(inner, t, reviewed.terms(), account_open, &progress);
            inner.gap(space::S4);
            let cancelled = cancel_control(inner, t, account_open);
            // A take press wins over a cancel. Both cannot happen in one frame, and the order states
            // which intent is honoured if that ever stops being true.
            took.or(cancelled)
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

/// The field an offer is pasted, scanned or dropped into, remembered across frames.
///
/// The line under the input is one line at a time, and which one it is says what the field is doing:
/// the drop invitation normally, what to let go of while a file is over the card, and — replacing
/// both — why the last dropped file could not be loaded, until another drop or an edit answers it.
fn paste_field(flow: &mut Flow, t: &Tokens, carrying: bool) -> String {
    let element = element();
    let live = flow.live();
    let (mut typed, problem): (String, Option<String>) = flow.place(|ui, _| {
        (
            0.0,
            ui.data(|d| {
                (
                    d.get_temp(element.with("text")).unwrap_or_default(),
                    d.get_temp(element.with("problem")),
                )
            }),
        )
    });
    let before = typed.clone();

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
                    help: hint_while(carrying),
                    // A drag in progress outranks an old complaint: the person is already acting on
                    // it, and the sentence they need next is what letting go will do.
                    error: match carrying {
                        true => None,
                        false => problem,
                    },
                    id: element.with("text"),
                },
                &mut typed,
            ),
            (),
        )
    });
    let edited = typed != before;
    flow.place(|ui, _| {
        ui.data_mut(|d| {
            d.insert_temp(element.with("text"), typed.clone());
            // Typing is an answer to the complaint. Leaving it up would leave a refusal about a file
            // hanging over text the person has since replaced by hand.
            if edited {
                d.remove_temp::<String>(element.with("problem"));
            }
        });
        (0.0, ())
    });
    typed
}

/// The line under the input while a file is, or is not, being dragged over the card.
fn hint_while(carrying: bool) -> &'static str {
    match carrying {
        true => copy::offer::DROP_ACTIVE,
        false => copy::offer::PASTE_HINT,
    }
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

/// The control that cancels an offer this wallet made, under the sentence saying what that does.
///
/// # Why it is offered on any readable offer rather than only on one this wallet made
///
/// Whether an offer's coins are still this wallet's to reclaim is a CHAIN question — `cancel_build`
/// answers it from the offer's own coins — and this card performs no chain read. The two available
/// designs were therefore a control that is sometimes refused with a clear reason, or no cancel
/// control at all. A capability silently withheld reads as a missing feature, so the control is
/// offered and the refusal, when it comes, is `dig-offers`' own words: *already settled, or not the
/// maker's*.
///
/// It is a ghost-weight control beside the primary Take, because it is the rarer errand and the
/// destructive one; nothing about it is pre-selected or default.
fn cancel_control(flow: &mut Flow, t: &Tokens, account_open: bool) -> Option<TrayAction> {
    let progress = crate::wallet::cancelling::progress();
    if !matches!(progress, CancelProgress::Idle) {
        cancel_outcome(flow, t, &progress);
        flow.gap(space::S3);
    }

    flow.place(|ui, at| (text::caption(ui, at, t, copy::offer::CANCEL_ABOUT), ()));
    flow.gap(space::S2);

    let refusal = cancel_refusal_for(account_open, &progress);
    let live = flow.live();
    let pressed = flow.place(|ui, at| {
        let hit = paint::button_at(
            ui,
            egui::Rect::from_min_size(
                at.left_top(),
                egui::Vec2::new(
                    paint::button_width(ui, copy::offer::CANCEL_BUTTON),
                    paint::BUTTON_HEIGHT,
                ),
            ),
            element().with("cancel"),
            copy::offer::CANCEL_BUTTON,
            Weight::Ghost,
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
        true => Some(TrayAction::CancelOffer),
        false => None,
    }
}

/// Why the cancel control is refused, or `None` when it may be pressed.
///
/// There is no empty-terms case here, unlike the take control: an offer with nothing on either side
/// is not takeable, but its coins may still be this wallet's to reclaim, and refusing would strand
/// them.
fn cancel_refusal_for(account_open: bool, progress: &CancelProgress) -> Option<String> {
    if !account_open {
        return Some(copy::offer::CANCEL_REFUSED_LOCKED.to_string());
    }
    if matches!(progress, CancelProgress::Working) {
        return Some(copy::offer::CANCEL_REFUSED_IN_FLIGHT.to_string());
    }
    None
}

/// What became of the cancellation in flight.
///
/// [`CancelProgress::Broadcast`] is drawn Neutral rather than Good: a cancellation races any taker's
/// settlement, and a person who read it as final could reasonably spend the reclaimed coins again.
fn cancel_outcome(flow: &mut Flow, t: &Tokens, progress: &CancelProgress) {
    let (word, tone, body) = match progress {
        CancelProgress::Idle => return,
        CancelProgress::Working => (
            copy::offer::CANCEL_WORKING_BADGE,
            Tone::Neutral,
            copy::offer::CANCEL_WORKING_BODY.to_string(),
        ),
        CancelProgress::Broadcast { bundle_name } => (
            copy::offer::CANCEL_BROADCAST_BADGE,
            Tone::Neutral,
            copy::offer::cancel_broadcast_body(bundle_name),
        ),
        CancelProgress::Failed { why } => (
            copy::offer::CANCEL_FAILED_BADGE,
            Tone::Warn,
            copy::offer::cancel_failed_body(why),
        ),
    };

    flow.place(|ui, at| (data::badge(ui, at.left_top(), t, word, tone).height(), ()));
    flow.gap(space::S3);
    flow.place(|ui, at| (text::body(ui, at, t, &body), ()));
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

    /// A dropped file carrying `text` as its own bytes, so no temporary file is needed.
    fn carrying(name: &str, text: &str) -> egui::DroppedFile {
        egui::DroppedFile {
            name: name.to_string(),
            bytes: Some(std::sync::Arc::from(text.as_bytes())),
            ..Default::default()
        }
    }

    /// Raw input with `files` let go at `at`, as a backend delivers a drop.
    fn a_drop_at(at: egui::Pos2, files: Vec<egui::DroppedFile>) -> egui::RawInput {
        let mut raw = egui::RawInput {
            dropped_files: files,
            ..Default::default()
        };
        raw.events.push(egui::Event::PointerMoved(at));
        raw
    }

    /// **A drop is claimed by the card it was let go over, and by no other card.**
    ///
    /// The placement property, which needs TWO regions to be visible at all: an implementation that
    /// ignored the pointer and simply took `dropped_files` would satisfy "the card under the pointer
    /// got the file" on a one-region fixture, and would answer every other card's drops in the real
    /// pane. The second region is the honest control, and must come back empty on the same frame.
    #[test]
    fn a_drop_is_claimed_only_by_the_card_under_the_pointer() {
        let over_the_lower_card = egui::Pos2::new(20.0, 300.0);
        let ctx = egui::Context::default();

        let _ = ctx.run(
            a_drop_at(
                over_the_lower_card,
                vec![carrying("swap.offer", "offer1abc")],
            ),
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let offers =
                        egui::Rect::from_min_size(egui::Pos2::ZERO, egui::Vec2::new(400.0, 200.0));
                    let below = egui::Rect::from_min_size(
                        egui::Pos2::new(0.0, 240.0),
                        egui::Vec2::new(400.0, 200.0),
                    );

                    assert!(
                        dropped_onto(ui, below).is_some(),
                        "the card the file was let go over did not claim it"
                    );
                    assert!(
                        dropped_onto(ui, offers).is_none(),
                        "a file dropped on another card was also taken by the Offers card"
                    );
                    assert!(
                        !files_over(ui, offers),
                        "the Offers card lit up for a drag over another card"
                    );
                });
            },
        );
    }

    /// **A dropped file is judged by the SAME parser a paste is, so the drop path accepts no more
    /// than the paste path does.**
    ///
    /// The widening test this feature needs, and it has both halves. The control is a real offer,
    /// which must load and read; the abuse is a file that is plainly not an offer, which must reach
    /// the field and be REFUSED there. A drop path carrying its own, laxer notion of what an offer is
    /// would pass the control alone — which is exactly what makes a happy-path-only proof worthless
    /// here.
    #[test]
    fn dropped_text_is_read_by_the_same_parser_as_pasted_text() {
        let offer = an_offer_of(XCH_FOR_XCH);
        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                apply(ui, &[carrying("swap.offer", &offer)]);
                let loaded: String = ui
                    .data(|d| d.get_temp(element().with("text")))
                    .expect("the dropped offer reached the field");
                assert!(read(&loaded).is_ok(), "a dropped real offer did not read");

                apply(ui, &[carrying("notes.txt", "not an offer at all")]);
                let loaded: String = ui
                    .data(|d| d.get_temp(element().with("text")))
                    .expect("the dropped text reached the field");
                assert!(
                    matches!(read(&loaded), Err(Some(_))),
                    "a dropped file that is not an offer was not refused by the parser"
                );
            });
        });
    }

    /// **A file-level refusal is remembered and shown, and a later good drop clears it.**
    ///
    /// A silent no-op is the failure this guards: a person who drops a folder and sees nothing
    /// change cannot tell a refusal from an app that never noticed the drop. The clearing half is
    /// what stops the complaint outliving the file it was about.
    #[test]
    fn a_refused_drop_leaves_a_reason_and_a_good_one_takes_it_away() {
        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                apply(
                    ui,
                    &[carrying("a.offer", "one"), carrying("b.offer", "two")],
                );
                let why: String = ui
                    .data(|d| d.get_temp(element().with("problem")))
                    .expect("two files at once left no reason on screen");
                assert!(
                    why.contains('2'),
                    "the reason does not say what was wrong: {why}"
                );
                assert!(
                    ui.data(|d| d.get_temp::<String>(element().with("text")))
                        .is_none(),
                    "a refused drop still put something in the field"
                );

                apply(ui, &[carrying("swap.offer", "offer1abc")]);
                assert!(
                    ui.data(|d| d.get_temp::<String>(element().with("problem")))
                        .is_none(),
                    "the old complaint outlived the file it was about"
                );
            });
        });
    }

    /// **Dropping a valid offer loads it and takes nothing.**
    ///
    /// The money-consent property. The fixture is a REAL, takeable offer on an UNLOCKED account —
    /// the one arrangement in which a take could actually be reached — so a drop wired to the take
    /// path would be seen here. A fixture using an unreadable file or a locked account would be
    /// refused for an unrelated reason and could not tell the two apart.
    #[test]
    fn dropping_a_takeable_offer_loads_it_and_takes_nothing() {
        let offer = an_offer_of(XCH_FOR_XCH);
        let at = egui::Pos2::new(20.0, 20.0);
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);

        let acted = std::cell::Cell::new(None);
        let _ = ctx.run(a_drop_at(at, vec![carrying("swap.offer", &offer)]), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let column =
                    egui::Rect::from_min_size(egui::Pos2::ZERO, egui::Vec2::new(400.0, 2_000.0));
                let mut flow = Flow::new(ui, column, true);
                acted.set(card(&mut flow, &Tokens::DARK, true));
            });
        });

        assert_eq!(
            acted.get(),
            None,
            "a dropped file reached an action; loading an offer must never take one"
        );
    }

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
