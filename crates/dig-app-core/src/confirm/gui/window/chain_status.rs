//! The window's live view of the chain write happening right now (dig_ecosystem#2995, #3075).
//!
//! # One modal, raised by the FEED and by nothing else
//!
//! Every chain broadcast the app makes puts a [`Transaction`] on [`Feed`], and this module watches
//! that feed. When something unsettled is on it, the modal is up — wherever the broadcast came from.
//! No transaction site constructs it, passes it, or knows it exists, which is what makes it
//! impossible for a transaction site added later to forget it (dig_ecosystem#3075).
//!
//! # Why a modal is safe here, when the module used to argue it was not
//!
//! The defect behind #2995 was a window that stopped repainting for the length of a mainnet
//! ceremony, and this file previously concluded from that "a modal that owns the app for two
//! confirmations is that freeze with nicer pixels". That conclusion mistook a repaint failure for a
//! property of modals. The freeze is engineered around instead:
//!
//! * [`ctx.request_repaint`](egui::Context::request_repaint) is called on every frame the modal is
//!   drawn, and the progress bar moves on wall-clock time, so the animation is proof of life rather
//!   than decoration — a modal that has stopped painting is visibly a modal that has stopped.
//! * No work happens here. The bundle is being pushed and watched by a worker thread that has never
//!   heard of this surface, exactly as it was behind the sheet.
//!
//! # The escape rule is NOT waived
//!
//! `professional-ui`'s first hard rule stands: the modal takes Escape or **Hide** at any moment, and
//! putting it away does not touch the transaction — the worker runs on and the corner pill keeps the
//! live stage word. "Stays up until confirmed" means it never goes away BY ITSELF; the person can
//! always put it away. The **Done** affordance appears only once the transaction is settled, so the
//! surface can never claim a finish it does not have.
//!
//! # What it may say
//!
//! Only what [`Transaction`] holds, which is the point of that type existing: a broadcast is drawn
//! as a broadcast, never as a completion, and a cost that was never measured is drawn as nothing at
//! all rather than as zero.

use egui::{Rect, Vec2};

use super::pane::{action, card, data, flow::Flow, text};
use super::shell::{modal_height, modal_rect, scrim_over};
use super::Chrome;
use crate::confirm::gui::render::{rgba, space, Weight};
use crate::confirm::gui::theme::{Theme, Tokens};
use crate::transaction::{Feed, Stage, Transaction};

/// How wide the corner pill is drawn, at most.
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

/// The window's transaction modal: which ceremony step it is watching, and whether it is showing.
#[derive(Debug, Default)]
pub(crate) struct ChainStatus {
    /// Whether the person put the modal away for the current write.
    hidden: bool,
    /// The height the modal came to last frame, so it can be centred at its real size.
    ///
    /// Measured rather than declared, for the same reason the consent modal measures itself: the
    /// content is prose of an unknown length, and a fixed height is either a clipped id or a slab of
    /// empty card.
    height: f32,
    /// The `what` of the phase being watched, and how many phases have been seen before it.
    ///
    /// A ceremony is several bundles — creating a profile mints an identity, launches a store and
    /// commits its data — and each arrives on the feed as the same transaction under a new name. So
    /// the ordinal is COUNTED here from the names the feed publishes, and it is the only thing the
    /// modal claims about position. See [`step_line`] for why no total is ever stated.
    phase: Option<String>,
    /// How many phases of the current ceremony have been seen, the current one included.
    step: usize,
}

impl ChainStatus {
    /// Draw whatever `feed` is reporting, and act on anything pressed.
    ///
    /// Draws nothing at all when there is no chain write, which is almost always.
    pub(crate) fn draw(
        &mut self,
        ctx: &egui::Context,
        full: Rect,
        t: &Tokens,
        theme: Theme,
        feed: &Feed,
    ) {
        let Some(current) = feed.read() else {
            // Nothing in flight, so the next write starts visible and starts counting again. A
            // modal that stayed hidden because a PREVIOUS one was dismissed would silently swallow
            // the next spend.
            self.forget_the_ceremony();
            return;
        };
        self.count_the_phase(&current);

        let pressed = match self.hidden {
            true => self.pill(ctx, full, t, &current),
            false => self.modal(ctx, full, t, theme, &current),
        };

        match pressed {
            Some(Press::Hide) => self.hidden = true,
            Some(Press::Show) => self.hidden = false,
            Some(Press::Dismiss) => {
                // Only ever clears a SETTLED write — the feed refuses anything else, so a
                // mis-wired button here cannot make an in-flight spend disappear.
                feed.clear_if_settled();
                self.forget_the_ceremony();
            }
            None => {}
        }
    }

    /// Put the modal away, and say whether there was one to put away.
    ///
    /// This is how Escape reaches the modal: the shell asks first, and only closes the window when
    /// the answer is `false`. Escape on a surface that is watching a spend must mean *put this
    /// away*, never *quit the app in the middle of a ceremony*.
    ///
    /// Hiding, never clearing — the transaction is untouched and the pill keeps reporting it, which
    /// is the same promise the **Hide** button makes.
    pub(crate) fn take_escape(&mut self, feed: &Feed) -> bool {
        let showing = !self.hidden && feed.read().is_some();
        if showing {
            self.hidden = true;
        }
        showing
    }

    /// Note which phase of a ceremony `current` is, counting a newly-named phase as the next step.
    fn count_the_phase(&mut self, current: &Transaction) {
        if self.phase.as_deref() != Some(current.what.as_str()) {
            self.phase = Some(current.what.clone());
            self.step += 1;
        }
    }

    /// Start the next ceremony from nothing: showing, at step zero, watching no phase.
    fn forget_the_ceremony(&mut self) {
        self.hidden = false;
        self.phase = None;
        self.step = 0;
    }

    /// The modal itself: a scrim over the window, and the status centred on it.
    fn modal(
        &mut self,
        ctx: &egui::Context,
        full: Rect,
        t: &Tokens,
        theme: Theme,
        current: &Transaction,
    ) -> Option<Press> {
        // The whole answer to #2995's freeze. egui is lazy, and a surface that only repaints on
        // input would sit motionless through the minutes this modal exists to cover — which is
        // exactly what a crashed app looks like. The shell requests its own repaints too; this
        // one is stated here as well so the modal's liveness does not depend on a caller.
        ctx.request_repaint();
        self.scrim(ctx, full, t, theme);

        let at = modal_rect(full, Chrome::Dialog, self.height);
        let seconds = ctx.input(|i| i.time);
        let mut pressed = None;
        let mut bottom = at.top();
        // Above the scrim's layer, and above the panes, so the modal is the one thing under the
        // pointer that still answers to it.
        egui::Area::new(egui::Id::new("dig-app-chain-status"))
            .order(egui::Order::Tooltip)
            .fixed_pos(at.left_top())
            .show(ctx, |ui| {
                ui.set_clip_rect(at);
                let column =
                    Rect::from_min_size(at.left_top(), Vec2::new(at.width(), full.height()));
                let mut flow = Flow::new(ui, column, true);
                pressed = body(&mut flow, t, current, self.step, seconds);
                bottom = flow.cursor();
            });
        self.height = modal_height(full, at, bottom);
        pressed
    }

    /// The dimmed window behind the modal, drawn in the shell's own scrim colour.
    fn scrim(&self, ctx: &egui::Context, full: Rect, t: &Tokens, theme: Theme) {
        egui::Area::new(egui::Id::new("dig-app-chain-status-scrim"))
            .order(egui::Order::Foreground)
            .fixed_pos(full.left_top())
            .show(ctx, |ui| {
                ui.set_clip_rect(full);
                ui.painter()
                    .rect_filled(full, 0, rgba(scrim_over(t, theme)));
            });
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

/// The modal's content: what is happening, how far along, what it costs, and what may be pressed.
fn body(
    flow: &mut Flow,
    t: &Tokens,
    current: &Transaction,
    step: usize,
    seconds: f64,
) -> Option<Press> {
    let settled = current.is_settled();
    let stage = current.stage.clone();
    let money = current.money.clone();
    let title = current.what.clone();
    let position = step_line(step, current.more_to_come);

    flow.place(|ui, at| {
        let (height, pressed) = card::interactive_card(ui, at, t, true, Some(&title), |inner| {
            inner.place(|ui, at| {
                (
                    data::badge(ui, at.left_top(), t, stage.word(), tone(&stage)).height(),
                    (),
                )
            });

            // The bar carries no progress figure and is not meant to: nothing can say how far
            // through a mempool wait a bundle is, and a bar that crept to 90% and stopped would be
            // inventing one. It reports that the app is alive, and the words report the rest.
            if !stage.is_settled() {
                inner.gap(space::S4);
                inner.place(|ui, at| (indeterminate(ui, at, t, seconds), ()));
            }

            if let Some(position) = &position {
                inner.gap(space::S3);
                inner.place(|ui, at| (text::caption(ui, at, t, position), ()));
            }

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

/// How tall the indeterminate bar is drawn, matching the meter's bar so the two read as one family.
const BAR_HEIGHT: f32 = 8.0;

/// How much of the track the travelling segment occupies.
const BAR_SHARE: f32 = 0.35;

/// How long the segment takes to cross the track once, in seconds.
///
/// Slow enough to read as waiting rather than as loading, fast enough that a glance a second apart
/// sees it in two different places — which is the only thing it is claiming.
const BAR_PERIOD: f64 = 1.4;

/// The travelling segment's left edge, in points from the track's left edge.
///
/// A pure function of the track and the clock, so the animation is ASSERTABLE: that it stays inside
/// its track, and that it actually moves. A bar that had stopped would be the #2995 freeze wearing
/// this modal's face, and a test that could not tell the difference would be no guard at all.
fn bar_offset(track_width: f32, seconds: f64) -> f32 {
    let travel = (track_width - track_width * BAR_SHARE).max(0.0);
    let swept = (seconds.rem_euclid(BAR_PERIOD * 2.0)) / BAR_PERIOD;
    // Out and back rather than wrapping, so the segment never jumps discontinuously across the
    // track — a jump reads as a repaint glitch, which is the opposite of the reassurance intended.
    let fraction = match swept <= 1.0 {
        true => swept,
        false => 2.0 - swept,
    };
    travel * fraction as f32
}

/// The indeterminate bar: a track, and a segment travelling along it. Returns the height used.
fn indeterminate(ui: &mut egui::Ui, at: Rect, t: &Tokens, seconds: f64) -> f32 {
    let track = Rect::from_min_size(at.left_top(), Vec2::new(at.width(), BAR_HEIGHT));
    let corner = egui::CornerRadius::same((BAR_HEIGHT / 2.0) as u8);
    ui.painter()
        .rect_filled(track, corner, rgba(t.surface_2.over(t.surface)));
    let segment = Rect::from_min_size(
        egui::Pos2::new(
            track.left() + bar_offset(track.width(), seconds),
            track.top(),
        ),
        Vec2::new(track.width() * BAR_SHARE, BAR_HEIGHT),
    );
    ui.painter()
        .rect_filled(segment, corner, rgba(t.dig_purple));
    BAR_HEIGHT
}

/// Which step of a ceremony this is, or nothing when the write is a ceremony of one.
///
/// # Why it never says "of three"
///
/// The feed carries what a write IS and whether more follow it; no publisher declares how many
/// bundles a ceremony will take, and a creation's ladder can end early on a failure. So a total
/// would be a number this surface invented, drawn beside a real one — the same class of claim as
/// rendering an unmeasured cost as zero. What CAN be said honestly is which step is in flight and
/// whether more follow, and that is what is said.
fn step_line(step: usize, more_to_come: bool) -> Option<String> {
    match (step, more_to_come) {
        (0 | 1, false) => None,
        (step, true) => Some(format!(
            "Step {step} of this transaction. More steps follow once this one confirms."
        )),
        (step, false) => Some(format!("Step {step} of this transaction — the last one.")),
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

    /// A window big enough that nothing is clamped by its edges.
    fn window() -> Rect {
        Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(900.0, 600.0))
    }

    /// What one real paint of `status` against `feed` produced.
    struct Painted {
        /// Whether a scrim covering the window was drawn.
        scrimmed: bool,
        /// Where the status card ended up, if it was drawn at all.
        card: Option<Rect>,
        /// Whether the frame asked to be painted again immediately.
        repaints: bool,
    }

    impl Painted {
        /// Whether a person saw a MODAL: a scrimmed window with the status centred on it.
        ///
        /// Both halves are required because each alone is satisfied by the surface this replaced.
        /// The pre-#3075 sheet drew the same card, with the same content, in the bottom-right
        /// corner and with no scrim — so a test that only asked "was the card drawn" would pass
        /// against the very thing the user asked to be changed.
        fn is_a_modal(&self) -> bool {
            let centred = self.card.is_some_and(|card| {
                (card.center().x - window().center().x).abs() < window().width() * 0.1
            });
            self.scrimmed && centred
        }
    }

    /// Paint one real frame of `status` against `feed` and read back what it produced.
    ///
    /// Read from egui's own layers rather than from a field on the struct: the question this
    /// surface has to answer is "did a person see this", and `hidden == false` is a claim about
    /// intent, which a placement or ordering mistake would satisfy just as happily.
    fn paint(status: &mut ChainStatus, feed: &Feed) -> Painted {
        let ctx = egui::Context::default();
        super::super::install_fonts(&ctx);
        // Twice, and the SECOND frame is the one read. A freshly-built context always asks to be
        // painted again — it has fonts to load and a layout it has never done — so a first frame
        // says nothing about whether this surface is keeping itself alive.
        let mut output = None;
        for _ in 0..2 {
            output = Some(ctx.run(egui::RawInput::default(), |ctx| {
                status.draw(ctx, window(), &Tokens::LIGHT, Theme::Light, feed);
            }));
        }
        let output = output.expect("no frame was painted");
        Painted {
            scrimmed: ctx
                .memory(|m| m.area_rect(egui::Id::new("dig-app-chain-status-scrim")))
                .is_some(),
            card: ctx.memory(|m| m.area_rect(egui::Id::new("dig-app-chain-status"))),
            repaints: output
                .viewport_output
                .values()
                .any(|viewport| viewport.repaint_delay.is_zero()),
        }
    }

    /// Whether one real paint put the modal up.
    fn painted_modal(status: &mut ChainStatus, feed: &Feed) -> bool {
        paint(status, feed).is_a_modal()
    }

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
        let empty = Feed::detached();
        assert!(
            !painted_modal(&mut status, &empty),
            "a modal was drawn with nothing in flight"
        );
        assert!(
            !status.hidden,
            "the surface stayed hidden with no write in flight, so the next spend would be silent"
        );
    }

    /// **A broadcast published by production code this change never touched raises the modal.**
    ///
    /// The load-bearing property of dig_ecosystem#3075: the modal is raised by the FEED, so no
    /// transaction site opts in and none can forget to. The fixture is deliberately a real
    /// publisher — [`crate::account::creation_progress`], which this change does not modify and
    /// which the profile creation worker calls verbatim — rather than a hand-built [`Transaction`].
    /// A hand-built one would prove the modal can draw a struct, which is a different and much
    /// weaker claim than "what the app actually broadcasts raises it".
    ///
    /// The control is the same status against an EMPTY feed. Without it, a `draw` that painted a
    /// scrim unconditionally would pass.
    #[test]
    fn a_broadcast_from_an_unmodified_site_raises_the_modal() {
        use crate::account::creation_progress;

        let feed = Feed::detached();
        let mut status = ChainStatus::default();
        assert!(
            !painted_modal(&mut status, &feed),
            "the modal was up before anything was broadcast"
        );

        feed.publish(creation_progress::starting(20_002));
        assert!(
            painted_modal(&mut status, &feed),
            "a transaction on the feed did not raise the modal, so a broadcast can happen unseen"
        );
    }

    /// **Escape puts the modal away and the transaction carries on.**
    ///
    /// Both halves matter and they pull in opposite directions: a modal that cannot be escaped traps
    /// the person, and an escape that cancelled the ceremony would lose their money. So the feed is
    /// re-read afterwards — asserting only `hidden` would pass for an implementation that cleared
    /// the write on the way out.
    #[test]
    fn escape_puts_the_modal_away_without_touching_the_transaction() {
        let feed = Feed::detached();
        let base = Transaction::starting("Sending XCH", None);
        feed.publish(base.at(Stage::Pushed {
            id: "0xabc".to_string(),
        }));

        let mut status = ChainStatus::default();
        assert!(painted_modal(&mut status, &feed), "the modal never came up");
        assert!(
            status.take_escape(&feed),
            "Escape was refused while the modal was up"
        );

        assert!(
            !painted_modal(&mut status, &feed),
            "Escape left the modal up, so there is no way out of it"
        );
        assert_eq!(
            feed.read().map(|t| t.stage),
            Some(Stage::Pushed {
                id: "0xabc".to_string()
            }),
            "Escape abandoned the transaction"
        );
        assert!(
            !status.take_escape(&feed),
            "Escape was swallowed with the modal already away, so it could never close the window"
        );
    }

    /// **A three-bundle ceremony is counted as three steps, from the feed alone.**
    ///
    /// The user's stated case: creating a profile is three chain writes and each needs its own wait.
    /// The fixture publishes three DIFFERENTLY-NAMED phases with a confirmation between them,
    /// because that is the shape the real ceremony has — a mid-ceremony `Confirmed` that is not the
    /// end. A counter keyed on anything but the phase name would miscount it.
    #[test]
    fn each_phase_of_a_ceremony_is_counted_as_its_own_step() {
        let feed = Feed::detached();
        let base = Transaction::starting("Creating your profile", None);
        let mut status = ChainStatus::default();

        let phases = [
            "Creating your profile",
            "Creating your profile — launching your store",
            "Creating your profile — saving your details",
        ];
        for (index, phase) in phases.iter().enumerate() {
            feed.publish(base.mid_ceremony(
                *phase,
                Stage::Pushed {
                    id: format!("0x{index}"),
                },
            ));
            assert!(
                painted_modal(&mut status, &feed),
                "{phase} did not raise the modal"
            );
            assert_eq!(
                status.step,
                index + 1,
                "{phase} was counted as step {}",
                status.step
            );

            // The chain proves this bundle, and the ceremony is still not over.
            feed.publish(base.mid_ceremony(
                *phase,
                Stage::Confirmed {
                    height: 9_154_450 + index as u32,
                    made: "on chain".to_string(),
                },
            ));
            let _ = painted_modal(&mut status, &feed);
            assert_eq!(
                status.step,
                index + 1,
                "a confirmation was counted as a new step"
            );
        }

        // The ceremony ends, and the next one starts counting from one rather than from four.
        feed.publish(base.at(Stage::Confirmed {
            height: 9_154_460,
            made: "done".to_string(),
        }));
        let _ = painted_modal(&mut status, &feed);
        feed.clear_if_settled();
        let _ = painted_modal(&mut status, &feed);
        feed.publish(Transaction::starting("Sending XCH", None));
        let _ = painted_modal(&mut status, &feed);
        assert_eq!(
            status.step, 1,
            "a new ceremony inherited the last one's step count"
        );
    }

    /// **The step line says which step it is, and never how many there are.**
    ///
    /// No publisher declares a ceremony's length, so a total would be invented — the same class of
    /// claim as drawing an unmeasured cost as zero. The digit assertion is on the STRING because
    /// that is what a person reads; a total held only in a field would be harmless.
    #[test]
    fn the_step_line_never_invents_a_total() {
        assert_eq!(
            step_line(1, false),
            None,
            "a single spend was given step language"
        );
        let mid = step_line(2, true).expect("a mid-ceremony step said nothing about its position");
        assert!(
            mid.contains("Step 2"),
            "{mid} does not say which step it is"
        );
        assert!(
            mid.contains("More steps follow"),
            "{mid} hides that more spends are coming"
        );
        assert!(
            !mid.contains(" of 2") && !mid.contains(" of 3"),
            "{mid} invented a total"
        );
        let last = step_line(3, false).expect("the last step of a ceremony said nothing");
        assert!(
            last.contains("Step 3"),
            "{last} does not say which step it is"
        );
        assert!(
            !last.contains("More steps follow"),
            "{last} promises a step that is not coming"
        );
    }

    /// **A frame that draws the modal asks for the next one.**
    ///
    /// The dig_ecosystem#2995 guard, at the layer the freeze actually happened on. egui is lazy: a
    /// frame that does not request a repaint is the last frame drawn until something moves, and a
    /// motionless modal over a minutes-long mainnet wait is indistinguishable from the crash this
    /// module was written for. The bar's own arithmetic being correct proves nothing if no frame
    /// ever runs to draw it, which is why this is asserted on the frame rather than on the bar.
    ///
    /// The control is the same status with nothing in flight: a `draw` that requested a repaint
    /// unconditionally would burn a laptop's battery all day and would pass a one-sided test.
    ///
    /// # What this does NOT prove
    ///
    /// It asserts the PROPERTY, not one line of code. egui also schedules repaints of its own for
    /// the card's hover animations, and measurement confirms this test still passes with
    /// [`ChainStatus::modal`]'s explicit `request_repaint` removed. That call therefore stays as the
    /// guarantee — the incidental animations are an implementation detail of a widget that could
    /// stop animating tomorrow, and the modal's liveness must not rest on them.
    #[test]
    fn every_frame_that_draws_the_modal_asks_for_another() {
        let feed = Feed::detached();
        let mut status = ChainStatus::default();
        assert!(
            !paint(&mut status, &feed).repaints,
            "the window was kept spinning with no chain write in flight"
        );

        feed.publish(
            Transaction::starting("Sending XCH", None).at(Stage::Pushed {
                id: "0xabc".to_string(),
            }),
        );
        let painted = paint(&mut status, &feed);
        assert!(painted.is_a_modal(), "the modal never came up");
        assert!(
            painted.repaints,
            "the modal drew one frame and asked for no more, so it would sit frozen"
        );
    }

    /// **The bar stays inside its track, and it moves.**
    ///
    /// Movement is the whole point (dig_ecosystem#2995): a modal that stopped painting looks exactly
    /// like a frozen app, and the animation is the proof of life. Sampled across four full periods
    /// rather than at two instants, because a bar that only moved for the first half second would
    /// satisfy a two-sample test and still stop while a person watched.
    #[test]
    fn the_bar_travels_inside_its_track_and_never_stalls() {
        let width = 320.0;
        let travel = width - width * BAR_SHARE;
        let mut seen: Vec<f32> = Vec::new();
        let mut at = 0.0;
        while at < BAR_PERIOD * 4.0 {
            let offset = bar_offset(width, at);
            assert!(
                (0.0..=travel + f32::EPSILON).contains(&offset),
                "at {at}s the bar sat at {offset}, outside a {travel}-wide travel"
            );
            seen.push(offset);
            at += BAR_PERIOD / 8.0;
        }
        // Every consecutive pair differs, so the bar is never motionless for a sampled interval.
        assert!(
            seen.windows(2).all(|pair| (pair[0] - pair[1]).abs() > 1.0),
            "the bar stopped moving somewhere in {seen:?}"
        );
        // A track with no room to travel in is arithmetic, not a panic or a NaN.
        assert_eq!(
            bar_offset(0.0, 3.5),
            0.0,
            "a zero-width track produced a position"
        );
    }

    /// **An unconfirmed write is never offered a way to finish.**
    ///
    /// The modal's version of the honesty rule: `Pushed` is the state the person waits in, and a
    /// **Done** button there would let them close a surface that had proved nothing. The fixture is
    /// a mid-ceremony CONFIRMATION rather than a push, because that is the case a settledness check
    /// reading the stage instead of the transaction would get wrong.
    #[test]
    fn an_unconfirmed_write_is_never_offered_a_finish() {
        let unsettled = Transaction::starting("Creating your profile", None).mid_ceremony(
            "Creating your profile",
            Stage::Confirmed {
                height: 9_154_450,
                made: "half".to_string(),
            },
        );
        assert!(
            !unsettled.is_settled(),
            "a mid-ceremony confirmation read as the end"
        );
        assert_eq!(
            controls(unsettled.is_settled())[0].id,
            Press::Hide,
            "a ceremony still holding the person's money offered to be finished"
        );
    }
}
