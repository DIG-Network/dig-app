//! The Wallet tab's MAKE-AN-OFFER card: choose what you give and what you want, get a string to
//! share (dig_ecosystem#3077).
//!
//! # Why this is a card of its own and not a mode of the offer card
//!
//! Reading an offer and writing one are different errands with different inputs. A single card that
//! switched between them would make the person choose a mode before they could see either, and would
//! put a paste field and a pair of amount fields on the same surface where only one is ever wanted.
//!
//! # The one thing this card must never imply
//!
//! **A made offer is not a completed trade.** What the maker gives is committed the moment the offer
//! exists; what they asked for arrives only if somebody takes it, and nobody is obliged to. So the
//! success state is worded as *ready to share*, never as done, and the same asymmetry is stated at
//! the custody confirm gate through [`crate::wallet::offer_words::MAKE_CAUTION`].
//!
//! # Why the given side is XCH and the wanted side has a chooser
//!
//! [`crate::wallet::making`] can offer only XCH today — a CAT-offered coin needs a lineage proof the
//! app's coin read does not carry — while the WANTED side is merely asserted and so may be either
//! XCH or **$DIG**. The card states that limit rather than presenting a control that would fail at
//! build time.

use super::card;
use super::copy;
use super::data::{self, Tone, Value};
use super::field;
use super::flow::Flow;
use super::identity;
use super::select::{self, Choice, Select};
use super::text;
use crate::amount::{parse_asset_amount, AmountProblem};
use crate::confirm::gui::paint;
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::tray_menu::TrayAction;
use crate::wallet::making::{MakeProgress, Wanted};
use crate::wallet::state::Asset;

/// The id the form's fields are remembered under between frames.
fn element() -> egui::Id {
    egui::Id::new("dig-window-wallet-make-offer")
}

/// Draw the make-an-offer card and report the action pressed.
///
/// `account_open` is the account's own state, not a re-derived rule: making an offer signs a spend,
/// and a locked account must say so on the control rather than at signing time.
pub(crate) fn card(flow: &mut Flow, t: &Tokens, account_open: bool) -> Option<TrayAction> {
    let live = flow.live();
    flow.place(|ui, at| {
        let pressed =
            card::interactive_card(ui, at, t, live, Some(copy::make_offer::CARD), |inner| {
                body(inner, t, account_open)
            });
        (pressed.0, pressed.1.flatten())
    })
}

/// The card's contents: whatever state the make is in, then the form and the control.
fn body(inner: &mut Flow, t: &Tokens, account_open: bool) -> Option<TrayAction> {
    let progress = crate::wallet::making::progress();
    if !matches!(progress, MakeProgress::Idle) {
        outcome(inner, t, &progress);
        inner.gap(space::S4);
    }

    inner.place(|ui, at| (text::caption(ui, at, t, copy::make_offer::ABOUT), ()));
    inner.gap(space::S3);

    let give = amount_field(inner, t, "give", copy::make_offer::GIVE_LABEL, Asset::Xch);
    inner.gap(space::S3);
    let want_asset = asset_chooser(inner, t);
    inner.gap(space::S3);
    let want = amount_field(inner, t, "want", copy::make_offer::WANT_LABEL, want_asset);

    // Staged on EVERY frame, including as `None`, so what the shell would make always matches what
    // the form is showing. Staging only on a valid form would leave the last good draft armed after
    // a person had cleared or changed a field.
    let draft = draft_from(give, want_asset, want);
    crate::wallet::making::stage(draft.clone());

    inner.gap(space::S4);
    make_control(inner, t, draft.is_some(), account_open, &progress)
}

/// The draft the two fields describe, or `None` while either is not yet an amount.
///
/// Both sides must parse AND be non-zero, which is [`MakeDraft::checked`]'s rule — asked here rather
/// than restated, so the control's enabled-ness and the builder's refusal cannot drift apart.
fn draft_from(
    give: Result<u64, AmountProblem>,
    want_asset: Asset,
    want: Result<u64, AmountProblem>,
) -> Option<crate::wallet::making::MakeDraft> {
    let (Ok(give), Ok(want)) = (give, want) else {
        return None;
    };
    let wanted = match want_asset {
        Asset::Xch => Wanted::Xch { mojos: want },
        Asset::Dig => Wanted::Cat {
            asset_id: dig_constants::DIG_ASSET_ID,
            amount: want,
        },
    };
    crate::wallet::making::MakeDraft::checked(give, wanted).ok()
}

/// One amount field, in the units of `asset`, reporting what it parses to.
///
/// The error is drawn from the parse rather than from a length or a character check, so the sentence
/// a person reads is the same rule the number is actually held to.
fn amount_field(
    flow: &mut Flow,
    t: &Tokens,
    slot: &'static str,
    label: &'static str,
    asset: Asset,
) -> Result<u64, AmountProblem> {
    let id = element().with(slot);
    let mut typed: String =
        flow.place(|ui, _| (0.0, ui.data(|d| d.get_temp(id)).unwrap_or_default()));

    let parsed = parse_asset_amount(asset, &typed);
    let error = match &parsed {
        // An untouched field is not a mistake, so the empty case draws no error.
        Err(AmountProblem::Empty) => None,
        Err(problem) => Some(crate::wallet::sending::amount_sentence(asset, *problem)),
        Ok(_) => None,
    };

    flow.place(|ui, at| {
        (
            field::text_field(
                ui,
                at,
                t,
                flow_live(ui),
                &field::Field {
                    label,
                    placeholder: copy::make_offer::AMOUNT_PLACEHOLDER,
                    help: copy::make_offer::amount_help(asset),
                    error: error.clone(),
                    id,
                },
                &mut typed,
            ),
            (),
        )
    });
    flow.place(|ui, _| {
        ui.data_mut(|d| d.insert_temp(id, typed.clone()));
        (0.0, ())
    });
    parsed
}

/// Whether the pane is interactive, read from the ui rather than threaded through every helper.
fn flow_live(ui: &egui::Ui) -> bool {
    ui.is_enabled()
}

/// The chooser for what the offer asks for.
fn asset_chooser(flow: &mut Flow, t: &Tokens) -> Asset {
    let id = element().with("want-asset");
    let stored: Option<Asset> = flow.place(|ui, _| (0.0, ui.data(|d| d.get_temp(id))));
    let selected = stored.unwrap_or(Asset::Xch);
    let options = [
        Choice {
            label: copy::make_offer::ASSET_XCH.to_string(),
            id: Asset::Xch,
        },
        Choice {
            label: copy::make_offer::ASSET_DIG.to_string(),
            id: Asset::Dig,
        },
    ];
    let at = options.iter().position(|choice| choice.id == selected);
    let live = flow.live();

    let chosen = flow.place(|ui, at_rect| {
        select::select(
            ui,
            at_rect,
            t,
            live,
            &Select {
                label: copy::make_offer::WANT_ASSET_LABEL,
                options: &options,
                selected: at,
                unknown: copy::make_offer::ASSET_XCH,
                id: id.with("control"),
            },
        )
    });

    let chosen = chosen.unwrap_or(selected);
    flow.place(|ui, _| {
        ui.data_mut(|d| d.insert_temp(id, chosen));
        (0.0, ())
    });
    chosen
}

/// The control that makes the offer, and — when it is refused — the reason under it.
///
/// `professional-ui`'s never-trap rule: a control that cannot be pressed says why, where the person
/// is already looking, and every refusal is a real precondition rather than a guess.
fn make_control(
    flow: &mut Flow,
    t: &Tokens,
    form_complete: bool,
    account_open: bool,
    progress: &MakeProgress,
) -> Option<TrayAction> {
    let refusal = refusal_for(form_complete, account_open, progress);
    let live = flow.live();
    let pressed = flow.place(|ui, at| {
        let hit = paint::button_at(
            ui,
            egui::Rect::from_min_size(
                at.left_top(),
                egui::Vec2::new(
                    paint::button_width(ui, copy::make_offer::MAKE_BUTTON),
                    paint::BUTTON_HEIGHT,
                ),
            ),
            element().with("make"),
            copy::make_offer::MAKE_BUTTON,
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
        true => Some(TrayAction::MakeOffer),
        false => None,
    }
}

/// Why the make control is refused, or `None` when it may be pressed.
///
/// Ordered by what a person can act on soonest: the form is in front of them, the lock is one press
/// away, and an in-flight make is a wait.
fn refusal_for(form_complete: bool, account_open: bool, progress: &MakeProgress) -> Option<String> {
    if !form_complete {
        return Some(copy::make_offer::REFUSED_INCOMPLETE.to_string());
    }
    if !account_open {
        return Some(copy::make_offer::REFUSED_LOCKED.to_string());
    }
    if matches!(progress, MakeProgress::Working) {
        return Some(copy::make_offer::REFUSED_IN_FLIGHT.to_string());
    }
    None
}

/// What became of the make in flight, drawn as the state it actually is.
///
/// The success state carries the whole `offer1…` string with a copy control, because an offer nobody
/// can lift off the screen is an offer that was not really made — and it is a value nobody types.
fn outcome(flow: &mut Flow, t: &Tokens, progress: &MakeProgress) {
    let (word, tone, body) = match progress {
        MakeProgress::Idle => return,
        MakeProgress::Working => (
            copy::make_offer::WORKING_BADGE,
            Tone::Neutral,
            copy::make_offer::WORKING_BODY.to_string(),
        ),
        MakeProgress::Made { .. } => (
            copy::make_offer::MADE_BADGE,
            Tone::Good,
            copy::make_offer::MADE_BODY.to_string(),
        ),
        MakeProgress::Failed { why } => (
            copy::make_offer::FAILED_BADGE,
            Tone::Warn,
            copy::make_offer::failed_body(why),
        ),
    };

    flow.place(|ui, at| (data::badge(ui, at.left_top(), t, word, tone).height(), ()));
    flow.gap(space::S3);
    flow.place(|ui, at| (text::body(ui, at, t, &body), ()));

    if let MakeProgress::Made { offer } = progress {
        flow.gap(space::S3);
        let offer = offer.clone();
        let live = flow.live();
        flow.place(|ui, at| {
            (
                identity::copyable(
                    ui,
                    at,
                    t,
                    copy::make_offer::MADE_LABEL,
                    &Value::Identifier(offer.clone()),
                    element().with("made"),
                    live,
                ),
                (),
            )
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Every refusal is reachable, distinguishable, and a complete form is refused by nothing.**
    ///
    /// Each case varies exactly ONE precondition away from the makeable control, so a rule that
    /// refused everything and a rule that refused nothing both fail — which a single hostile fixture
    /// could not see.
    #[test]
    fn each_refusal_names_its_own_precondition_and_a_complete_form_names_none() {
        assert_eq!(refusal_for(true, true, &MakeProgress::Idle), None);

        let incomplete = refusal_for(false, true, &MakeProgress::Idle)
            .expect("a half-filled form cannot be made");
        let locked =
            refusal_for(true, false, &MakeProgress::Idle).expect("a locked account cannot sign");
        let in_flight = refusal_for(true, true, &MakeProgress::Working)
            .expect("a second make is refused while one is in flight");

        assert_ne!(incomplete, locked);
        assert_ne!(locked, in_flight);
        assert_ne!(incomplete, in_flight);
    }

    /// **The wanted side follows the CHOOSER, not the typed digits.**
    ///
    /// The same text means different amounts in the two assets — `"1"` is 10^12 mojos and 1,000 $DIG
    /// base units — so the fixture holds the digits FIXED and varies only the asset. A builder that
    /// ignored the chooser produces identical drafts here and fails; one that swapped the assets
    /// produces the other's figure.
    #[test]
    fn the_wanted_asset_decides_what_the_typed_amount_means() {
        let xch = draft_from(Ok(500), Asset::Xch, Ok(1_000)).expect("both sides are non-zero");
        let dig = draft_from(Ok(500), Asset::Dig, Ok(1_000)).expect("both sides are non-zero");

        assert_eq!(xch.want(), &Wanted::Xch { mojos: 1_000 });
        assert_eq!(
            dig.want(),
            &Wanted::Cat {
                asset_id: dig_constants::DIG_ASSET_ID,
                amount: 1_000
            }
        );
        assert_ne!(xch.want(), dig.want());
    }

    /// **An unparseable or zero side yields no draft at all.**
    ///
    /// The control's enabled-ness is exactly "a draft exists", so this is the assertion that keeps a
    /// person from pressing a button whose spend would be refused a moment later.
    #[test]
    fn a_form_that_is_not_yet_an_offer_produces_no_draft() {
        assert!(draft_from(Err(AmountProblem::Empty), Asset::Xch, Ok(1)).is_none());
        assert!(draft_from(Ok(1), Asset::Xch, Err(AmountProblem::NotANumber)).is_none());
        assert!(draft_from(Ok(0), Asset::Xch, Ok(1)).is_none());
        assert!(draft_from(Ok(1), Asset::Xch, Ok(0)).is_none());
        assert!(draft_from(Ok(1), Asset::Xch, Ok(1)).is_some());
    }
}
