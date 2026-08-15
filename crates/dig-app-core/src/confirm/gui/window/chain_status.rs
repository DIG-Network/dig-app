//! The window's live view of the chain write happening right now (dig_ecosystem#2995).
//!
//! # Why this is not a modal
//!
//! The defect this answers is a window that stopped repainting for the length of a mainnet
//! ceremony, and a modal that owns the app for two confirmations is that freeze with nicer pixels.
//! `professional-ui`'s first hard rule forbids trapping the person, and a chain write takes minutes:
//! long enough that "wait here" is not an acceptable thing to ask.
//!
//! So the status is a **sheet**, not a modal. It floats over the app at the bottom right, above the
//! panes and below any consent prompt, it takes no scrim, it blocks nothing, and it can be put away
//! at any moment. Putting it away does not touch the transaction — a worker is doing that, and it
//! keeps going — and while a write is in flight a pill stays in the same corner to bring the sheet
//! back. There is no state in which a person can lose sight of a spend they started.
//!
//! # What it may say
//!
//! Only what [`Transaction`] holds, which is the point of that type existing: a broadcast is drawn
//! as a broadcast, never as a completion, and a cost that was never measured is drawn as nothing at
//! all rather than as zero.

use egui::{Rect, Vec2};

use super::pane::{action, card, data, flow::Flow, text};
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::transaction::{Feed, Stage, Transaction};

/// How wide the sheet is drawn, at most.
///
/// Wide enough for a full 64-character coin id to wrap onto two lines rather than five, narrow
/// enough that it never reads as a second pane.
const SHEET_WIDTH: f32 = 420.0;

/// The gap between the sheet and the window's edges.
const MARGIN: f32 = space::S4;

/// What the person can press on the sheet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Press {
    /// Put the sheet away. The transaction is untouched.
    Hide,
    /// Put a FINISHED transaction away for good.
    Dismiss,
    /// Bring the sheet back.
    Show,
}

/// The label that puts an in-flight write's sheet away.
const HIDE: &str = "Hide";

/// The label that clears a finished write.
const DISMISS: &str = "Done";

/// The line under an in-flight write's controls, promising what hiding does NOT do.
///
/// Said on the surface rather than left to be discovered, because the fear this sheet exists to
/// remove is precisely "if I touch anything, will I lose the thing I paid for?".
const KEEPS_GOING: &str = "DIG keeps working on this whether or not this is showing. Closing the \
                           window is safe; quitting DIG is not.";

/// The window's transaction sheet, and whether it is showing.
#[derive(Debug, Default)]
pub(crate) struct ChainStatus {
    /// Whether the person put the sheet away for the current write.
    hidden: bool,
    /// The height the sheet came to last frame, so it can be drawn bottom-anchored.
    ///
    /// Measured rather than declared, for the same reason the in-window modal measures itself: the
    /// content is prose of an unknown length, and a fixed height is either a clipped id or a slab of
    /// empty card.
    height: f32,
}

impl ChainStatus {
    /// Draw whatever `feed` is reporting, and act on anything pressed.
    ///
    /// Draws nothing at all when there is no chain write, which is almost always.
    pub(crate) fn draw(&mut self, ctx: &egui::Context, full: Rect, t: &Tokens, feed: &Feed) {
        let Some(current) = feed.read() else {
            // Nothing in flight, so the next write starts visible. A sheet that stayed hidden
            // because a PREVIOUS one was dismissed would silently swallow the next spend.
            self.hidden = false;
            return;
        };

        let pressed = match self.hidden {
            true => self.pill(ctx, full, t, &current),
            false => self.sheet(ctx, full, t, &current),
        };

        match pressed {
            Some(Press::Hide) => self.hidden = true,
            Some(Press::Show) => self.hidden = false,
            Some(Press::Dismiss) => {
                // Only ever clears a SETTLED write — the feed refuses anything else, so a
                // mis-wired button here cannot make an in-flight spend disappear.
                feed.clear_if_settled();
                self.hidden = false;
            }
            None => {}
        }
    }

    /// The sheet itself, bottom-right, above the panes.
    fn sheet(
        &mut self,
        ctx: &egui::Context,
        full: Rect,
        t: &Tokens,
        current: &Transaction,
    ) -> Option<Press> {
        let width = SHEET_WIDTH.min(full.width() - MARGIN * 2.0);
        let at = Rect::from_min_size(
            egui::Pos2::new(
                full.right() - MARGIN - width,
                (full.bottom() - MARGIN - self.height).max(full.top() + MARGIN),
            ),
            Vec2::new(width, self.height.max(1.0)),
        );

        let mut pressed = None;
        let mut bottom = at.top();
        egui::Area::new(egui::Id::new("dig-app-chain-status"))
            .order(egui::Order::Middle)
            .fixed_pos(at.left_top())
            .show(ctx, |ui| {
                let column = Rect::from_min_size(at.left_top(), Vec2::new(width, full.height()));
                let mut flow = Flow::new(ui, column, true);
                pressed = body(&mut flow, t, current);
                bottom = flow.cursor();
            });
        self.height = bottom - at.top();
        pressed
    }

    /// The pill that brings a hidden sheet back.
    ///
    /// It says the STAGE, not a generic word, so a person who hid the sheet still learns from the
    /// corner of their eye that the thing they paid for confirmed.
    fn pill(
        &mut self,
        ctx: &egui::Context,
        full: Rect,
        t: &Tokens,
        current: &Transaction,
    ) -> Option<Press> {
        let mut pressed = None;
        egui::Area::new(egui::Id::new("dig-app-chain-status-pill"))
            .order(egui::Order::Middle)
            .fixed_pos(egui::Pos2::new(
                full.right() - MARGIN - PILL_WIDTH,
                full.bottom() - MARGIN - paint_button_height(),
            ))
            .show(ctx, |ui| {
                let at = Rect::from_min_size(
                    ui.next_widget_position(),
                    Vec2::new(PILL_WIDTH, paint_button_height()),
                );
                let (_, hit) = action::buttons(
                    ui,
                    at,
                    t,
                    true,
                    &[act(
                        format!("{} — {}", current.what, current.stage.word()),
                        Weight::Ghost,
                        Press::Show,
                        "dig-app-chain-status-show",
                    )],
                );
                pressed = hit;
            });
        pressed
    }
}

/// How wide the re-open pill is allowed to be.
const PILL_WIDTH: f32 = SHEET_WIDTH;

/// The height of one button, which is what the pill is.
fn paint_button_height() -> f32 {
    crate::confirm::gui::paint::BUTTON_HEIGHT
}

/// One action, spelled out so the four call sites below stay readable.
fn act(label: String, weight: Weight, id: Press, element: &str) -> action::Action<Press> {
    action::Action {
        label,
        weight,
        enabled: true,
        id,
        element: egui::Id::new(element),
    }
}

/// The sheet's content: what is happening, what it costs, and what may be pressed.
fn body(flow: &mut Flow, t: &Tokens, current: &Transaction) -> Option<Press> {
    let settled = current.is_settled();
    let stage = current.stage.clone();
    let money = current.money.clone();
    let title = current.what.clone();

    flow.place(|ui, at| {
        let (height, pressed) = card::interactive_card(ui, at, t, true, Some(&title), |inner| {
            inner.place(|ui, at| {
                (
                    data::badge(ui, at.left_top(), t, stage.word(), tone(&stage)).height(),
                    (),
                )
            });
            inner.gap(space::S3);
            inner.place(|ui, at| (text::body(ui, at, t, &stage.detail()), ()));

            // The cost, whenever it is known — on EVERY stage, because the question "how much
            // is this costing me?" does not stop being asked once the bundle is sent.
            if let Some(money) = &money {
                inner.gap(space::S3);
                inner.place(|ui, at| (text::caption(ui, at, t, &money.line()), ()));
            }

            inner.gap(space::S4);
            let hit = inner.place(|ui, at| action::buttons(ui, at, t, true, &controls(settled)));

            if !stage.is_settled() {
                inner.gap(space::S3);
                inner.place(|ui, at| (text::caption(ui, at, t, KEEPS_GOING), ()));
            }
            hit
        });
        (height, pressed.flatten())
    })
}

/// What may be pressed at `stage`.
///
/// There is ALWAYS exactly one control, in every state: an in-flight write can be put away, and a
/// settled one can be cleared. A state with no control is a surface a person cannot leave.
///
/// Takes the TRANSACTION's settledness, never the stage's: a mid-ceremony confirmation is a proved
/// bundle inside an unfinished ceremony, and offering to clear it would drop a surface that is still
/// holding the person's money.
fn controls(settled: bool) -> Vec<action::Action<Press>> {
    match settled {
        true => vec![act(
            DISMISS.to_string(),
            Weight::Primary,
            Press::Dismiss,
            "dig-app-chain-status-dismiss",
        )],
        false => vec![act(
            HIDE.to_string(),
            Weight::Ghost,
            Press::Hide,
            "dig-app-chain-status-hide",
        )],
    }
}

/// The badge's colour, which must never say more than the stage does.
///
/// A push is NEUTRAL, not positive: green on a broadcast is the same lie as the word "Sent" on its
/// own, told faster, and colour is read before words are. A stopped write takes `Warn` rather than
/// a danger tone — the money may well be safe on chain, and alarming a person into force-quitting
/// is the outcome this whole surface exists to prevent.
fn tone(stage: &Stage) -> data::Tone {
    match stage {
        Stage::Confirmed { .. } => data::Tone::Good,
        Stage::Failed { .. } => data::Tone::Warn,
        Stage::Building | Stage::Signing | Stage::Pushed { .. } => data::Tone::Neutral,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Money;

    /// Every stage a write can be in, as fixtures.
    fn every_stage() -> Vec<Stage> {
        vec![
            Stage::Building,
            Stage::Signing,
            Stage::Pushed {
                id: "0xe4e2b74f915e7f4a739b305aa086aa657a09a8a4df231d9307bb265c528ecc12"
                    .to_string(),
            },
            Stage::Confirmed {
                height: 9_154_450,
                made: "did:chia:1mhdr5h6".to_string(),
            },
            Stage::Failed {
                why: "The node stopped answering.".to_string(),
                next: "Leave DIG running.".to_string(),
            },
        ]
    }

    /// **Every state offers a control, so the sheet is never a place a person is stuck.**
    #[test]
    fn every_stage_offers_a_way_out() {
        for stage in every_stage() {
            let controls = controls(stage.is_settled());
            assert_eq!(
                controls.len(),
                1,
                "{stage:?} offered {} controls",
                controls.len()
            );
            assert!(controls[0].enabled, "{stage:?} offered a dead control");
        }
    }

    /// **An in-flight write can only be HIDDEN; only a settled one can be dismissed.**
    ///
    /// The two verbs mean different things to the transaction underneath — one leaves it alone, the
    /// other forgets it — so offering the wrong one is offering to lose a spend.
    #[test]
    fn an_in_flight_write_is_hidden_and_a_finished_one_is_dismissed() {
        for stage in every_stage() {
            let offered = controls(stage.is_settled())[0].id;
            match stage.is_settled() {
                true => assert_eq!(offered, Press::Dismiss, "{stage:?} offered the wrong verb"),
                false => assert_eq!(offered, Press::Hide, "{stage:?} offered the wrong verb"),
            }
        }
    }

    /// **A broadcast is never coloured as a success.**
    ///
    /// Colour is read before words, so a green badge over `Sent to the blockchain` says confirmed to
    /// somebody who read nothing else. The fixture holds every stage rather than testing `Pushed`
    /// alone, because a `tone` that returned `Good` for everything would satisfy a single case.
    #[test]
    fn only_a_confirmation_is_coloured_as_one() {
        for stage in every_stage() {
            let good = tone(&stage) == data::Tone::Good;
            assert_eq!(
                good,
                stage.is_confirmed(),
                "{stage:?} was coloured {:?}, which does not match what it means",
                tone(&stage)
            );
        }
    }

    /// **Hiding the sheet leaves the transaction alone, and it can be brought back.**
    ///
    /// The property the whole sheet design turns on. Asserted through the feed, because "the
    /// transaction survived" is a fact about the feed and not about what was painted.
    #[test]
    fn hiding_the_sheet_does_not_touch_an_in_flight_transaction() {
        let feed = Feed::detached();
        let tx = Transaction::starting(
            "Creating your profile",
            Some(Money {
                amount_mojos: 20_002,
                fee_mojos: None,
            }),
        );
        feed.publish(tx.at(Stage::Pushed {
            id: "0xabc".to_string(),
        }));

        let mut status = ChainStatus {
            hidden: true,
            ..Default::default()
        };
        assert_eq!(
            feed.read().map(|t| t.stage),
            Some(Stage::Pushed {
                id: "0xabc".to_string()
            }),
            "hiding the sheet lost the transaction"
        );

        // And a new write always arrives visible, whatever the last one left behind.
        // Hidden again, and now with NOTHING in flight: the next write must not inherit the last
        // one's dismissal, or a spend would start silently.
        status.hidden = true;
        let ctx = egui::Context::default();
        let full = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(900.0, 600.0));
        let empty = Feed::detached();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            status.draw(ctx, full, &Tokens::LIGHT, &empty);
        });
        assert!(
            !status.hidden,
            "the sheet stayed hidden with no write in flight, so the next spend would be silent"
        );
    }
}
