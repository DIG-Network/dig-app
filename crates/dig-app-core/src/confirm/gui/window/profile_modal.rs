//! The per-profile **edit modal**: the one surface a person changes a profile from
//! (dig_ecosystem#3069, criterion 4).
//!
//! # It holds no authoritative copy of anything, and this is the rule the module exists to keep
//!
//! The only durable copy of a profile body's preimage is the sealed pending file dig_ecosystem#3066
//! writes BEFORE the spend is pushed. So this modal:
//!
//! * never calls or retries the body store;
//! * does not stay open until the save completes — [`EditService::save`] is called and the modal
//!   closes in the same frame, because the write is a worker's job from that instant onward;
//! * never repopulates a form from its own draft, so nothing here can outlive the file and be
//!   mistaken for it.
//!
//! Holding the body in modal state would reintroduce exactly the permanent loss #3066 exists to
//! remove: the root lands on chain, the app closes, and the preimage is gone forever.
//!
//! # It builds no progress surface
//!
//! dig_ecosystem#3075 ships ONE transaction modal, raised by the [`Feed`](crate::transaction::Feed)
//! itself for any broadcast, with no caller opting in — see [`super::chain_status`]. Saving here
//! puts a transaction on that feed, so the confirmation sheet is already up by the next repaint. A
//! second progress display would be two surfaces claiming one write.
//!
//! # Escape is never taken away
//!
//! `professional-ui`'s first hard rule. Escape and **Cancel** both close it, at any moment, and
//! closing before a save has been pressed abandons nothing but the typing — which is the one thing
//! here that was never anywhere else either.

use egui::{Rect, Vec2};

use super::pane::{action, card, flow::Flow, profile_edit, text};
use super::shell::{modal_height, modal_rect, scrim_over};
use super::Chrome;
use crate::confirm::gui::paint;
use crate::confirm::gui::render::{rgba, space, Weight};
use crate::confirm::gui::theme::{Theme, Tokens};
use crate::profile_edit::ProfileEditing;
use crate::window_model::Tab;

/// Which profile the person asked to edit.
///
/// Carries the `ix` and NOT an ordinal, for [`super::pane::profiles`]'s reason: an ordinal names a
/// different profile after a delete, and this one has a Save button on it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Editing {
    /// The profile's HD index — its stable identity in every control that acts on it.
    pub(crate) ix: u32,
    /// How it is named to a person, for the modal's title.
    pub(crate) name: String,
    /// Whether it is the profile the account is currently deriving at.
    ///
    /// Load-bearing while dig_ecosystem#3071 is unlanded: the app builds ONE `AccountEditSeam`, at
    /// the active profile's index, so the editor behind this modal can only reach that one. The
    /// modal is wired per profile throughout and says so honestly for the others rather than
    /// offering a form that would save somewhere else.
    pub(crate) active: bool,
}

/// The window's profile editor: which profile it is open on, and how tall it came out.
#[derive(Debug, Default)]
pub(crate) struct ProfileModal {
    /// The profile being edited, or nothing when the modal is closed.
    open: Option<Editing>,
    /// How far the form has been scrolled, in points from its top.
    ///
    /// The form is painted into rectangles it chooses rather than through egui's layout, so an
    /// `egui::ScrollArea` measures its content as empty and never offers a bar. The offset is kept
    /// here instead and applied to the flow's origin, which is the same thing one layer up.
    scroll: f32,
    /// The height the modal came to last frame, so it can be centred at its real size.
    ///
    /// Measured rather than declared, for the reason every modal here measures itself: the content
    /// is a form of an unknown length, and a fixed height is either a clipped control or a slab of
    /// empty card.
    height: f32,
}

impl ProfileModal {
    /// Open the modal on `profile`, replacing whatever it was open on.
    pub(crate) fn open(&mut self, profile: Editing) {
        self.open = Some(profile);
        // A new profile is a new form, read from the top. Keeping the previous one's offset would
        // open the modal part-way down a form the person has not seen the start of.
        self.scroll = 0.0;
    }

    /// Close it. The typing is dropped; nothing else is.
    pub(crate) fn close(&mut self) {
        self.open = None;
    }

    /// Whether it is up, which is what the shell asks before letting Escape close the window.
    pub(crate) fn is_open(&self) -> bool {
        self.open.is_some()
    }

    /// Take Escape, and say whether there was a modal to take it.
    ///
    /// The shell asks first and only closes the window when the answer is `false` — Escape on a
    /// form means *put this away*, never *quit the app*.
    pub(crate) fn take_escape(&mut self) -> bool {
        let showing = self.is_open();
        self.close();
        showing
    }

    /// Take this frame's wheel movement, and keep the form inside its own bounds.
    ///
    /// Clamped to what actually overflows, and to zero when nothing does: a form that scrolled past
    /// its own end would leave a person looking at empty card wondering what they had lost.
    fn take_scroll(&mut self, ctx: &egui::Context, at: Rect, content: f32) {
        let viewport = (at.height() - ACTION_BAND).max(1.0);
        let overflow = (content - viewport).max(0.0);
        let over_the_modal = ctx
            .input(|i| i.pointer.hover_pos())
            .is_some_and(|pointer| at.contains(pointer));
        let turned = match over_the_modal {
            true => ctx.input(|i| i.raw_scroll_delta.y),
            false => 0.0,
        };
        // Subtracted, because a wheel turn AWAY from the person moves the content up.
        self.scroll = (self.scroll - turned).clamp(0.0, overflow);
    }

    /// Draw the modal, if one is open.
    pub(crate) fn draw(
        &mut self,
        ctx: &egui::Context,
        full: Rect,
        t: &Tokens,
        theme: Theme,
        tab: &Tab,
        offer: ProfileEditing,
    ) {
        let Some(editing) = self.open.clone() else {
            return;
        };
        // egui is lazy, and a form that only repainted on input would stop animating the moment a
        // person stopped typing — which over a chain read looks like an app that has stopped.
        ctx.request_repaint();
        self.scrim(ctx, full, t, theme);

        let at = modal_rect(full, Chrome::Dialog, self.height);
        let mut closed = false;
        // How tall the content came out, measured in its own coordinates.
        let mut used = 0.0_f32;
        let mut content = 0.0_f32;
        // Taken BEFORE the frame is drawn, because the flow needs the offset to place its first
        // block. A wheel turn therefore lands on the next frame, which is the frame it was going to
        // be visible on anyway.
        let offset = self.scroll;
        egui::Area::new(egui::Id::new("dig-app-profile-modal"))
            .order(egui::Order::Foreground)
            .fixed_pos(at.left_top())
            .show(ctx, |ui| {
                // The action row is PINNED to the bottom of the modal and the form is drawn above
                // it. A profile form is taller than any modal is allowed to be -- `modal_rect` caps
                // a modal at a share of the window so a margin of scrim always shows -- so a Save
                // at the end of the flow lands below the modal's own bottom edge. A control that
                // exists and cannot be reached is worse than one that does not exist.
                let actions = Rect::from_min_size(
                    egui::Pos2::new(at.left(), at.bottom() - ACTION_BAND),
                    Vec2::new(at.width(), ACTION_BAND),
                );
                let column = Rect::from_min_size(
                    at.left_top(),
                    Vec2::new(at.width(), (actions.top() - at.top()).max(1.0)),
                );

                ui.set_clip_rect(column);
                let scrolled = Rect::from_min_size(
                    egui::Pos2::new(column.left(), column.top() - offset),
                    column.size(),
                );
                let mut flow = Flow::new(ui, scrolled, true);
                body(&mut flow, t, &editing, offer);
                content = flow.cursor() - scrolled.top();
                used = content + ACTION_BAND;

                // Outside the body's clip, so the row is drawn whatever the form did above it.
                ui.set_clip_rect(at);
                closed = action_row(ui, actions, t, &editing, tab, offer);
            });
        self.height = modal_height(full, at, at.top() + used);
        self.take_scroll(ctx, at, content);
        if closed {
            self.close();
        }
    }

    /// The dimmed window behind the modal, in the shell's own scrim colour.
    fn scrim(&self, ctx: &egui::Context, full: Rect, t: &Tokens, theme: Theme) {
        egui::Area::new(egui::Id::new("dig-app-profile-modal-scrim"))
            .order(egui::Order::Middle)
            .fixed_pos(full.left_top())
            .show(ctx, |ui| {
                ui.set_clip_rect(full);
                ui.painter()
                    .rect_filled(full, 0, rgba(scrim_over(t, theme)));
            });
    }
}

/// The modal's scrolling body: its title, and either the form or the honest state.
///
/// Draws no control. Everything a person presses is in the pinned row below, which is what makes
/// Save and Close reachable however long the form above them turns out to be.
fn body(flow: &mut Flow, t: &Tokens, editing: &Editing, offer: ProfileEditing) {
    flow.place(|ui, at| {
        let height = card::panel(ui, at, t, None, |inner| {
            inner.place(|ui, row| (text::heading(ui, row, t, &title(&editing.name)), ()));
            inner.gap(space::S4);

            match editing.active {
                true => profile_edit::modal_body(inner, t, offer),
                false => inaccessible(inner, t, &editing.name),
            }
        });
        (height, ())
    });
}

/// How tall the pinned control band is: one button, with the spacing step above and below it.
const ACTION_BAND: f32 = paint::BUTTON_HEIGHT + space::S4 * 2.0;

/// The pinned row: Save where one is on offer, and Close always. Reports whether to close.
///
/// # Why Close is drawn in every state without exception
///
/// `professional-ui`'s first hard rule. This row is drawn outside everything the form decides, so
/// no reading state, no blocked seam and no form long enough to overflow the modal can produce a
/// surface with no way out.
fn action_row(
    ui: &mut egui::Ui,
    at: Rect,
    t: &Tokens,
    editing: &Editing,
    tab: &Tab,
    offer: ProfileEditing,
) -> bool {
    ui.painter().rect_filled(at, 0, rgba(t.surface));

    let mut controls = Vec::new();
    // Offered only where the form behind it can actually be saved. A profile this build cannot
    // reach gets no Save at all, rather than one that is permanently unpressable.
    if editing.active {
        if let Some((label, ready)) = profile_edit::modal_save_offer(ui, tab, offer) {
            controls.push(action::Action {
                label,
                weight: Weight::Primary,
                enabled: ready,
                id: Press::Save,
                element: egui::Id::new("dig-app-profile-modal-save"),
            });
        }
    }
    controls.push(action::Action {
        label: CANCEL.to_string(),
        weight: Weight::Ghost,
        enabled: true,
        id: Press::Close,
        element: egui::Id::new("dig-app-profile-modal-cancel"),
    });

    let row = Rect::from_min_size(
        egui::Pos2::new(at.left() + space::S4, at.top() + space::S4),
        Vec2::new(
            (at.width() - space::S4 * 2.0).max(1.0),
            paint::BUTTON_HEIGHT,
        ),
    );
    match action::buttons(ui, row, t, true, &controls).1 {
        Some(Press::Save) => {
            // Handed over and then closed, in this order and in the same frame. From here the write
            // belongs to a worker and to #3075's transaction modal; nothing about it is kept in this
            // surface, which is the whole of the module header's invariant.
            profile_edit::modal_save(ui);
            true
        }
        Some(Press::Close) => true,
        None => false,
    }
}

/// What the pinned row can report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Press {
    /// Publish what was typed.
    Save,
    /// Put the modal away, changing nothing.
    Close,
}

/// The modal's title.
fn title(name: &str) -> String {
    format!("Edit {name}")
}

/// Said over a profile this build cannot reach.
///
/// # Why the modal opens at all rather than the button being disabled
///
/// A per-profile Edit control that is permanently disabled explains nothing and reads as a feature
/// that does not work. This says which profile DIG can change right now and what would make this
/// one reachable, and the control that does it — *Use this profile for this account* — is on the
/// card immediately behind this modal, which Cancel returns to.
///
/// It is a statement about THIS BUILD, not about DIG: dig_ecosystem#3071 makes the seam per-profile
/// and this state stops being reachable.
fn inaccessible(flow: &mut Flow, t: &Tokens, name: &str) {
    let said = unreachable_sentence(name);
    flow.place(|ui, at| (text::body(ui, at, t, &said), ()));
}

/// The sentence [`inaccessible`] paints.
///
/// Its own function so a test reads the words production uses, rather than a copy of them written
/// beside the assertion — a test that lowercases a sentence it authored itself asserts nothing.
fn unreachable_sentence(name: &str) -> String {
    format!(
        "DIG can only change the profile this account is currently using, and that is not {name} \
         right now. Put it in use with “Use {name} for this account”, then edit it here."
    )
}

/// The label that closes the modal without saving.
///
/// Says CLOSE rather than *cancel*, because nothing is in flight to cancel: it puts the form away,
/// and anything already published stays published.
const CANCEL: &str = "Close";

#[cfg(test)]
mod tests {
    use super::*;

    fn a_profile(active: bool) -> Editing {
        Editing {
            ix: 2,
            name: "“work”".to_string(),
            active,
        }
    }

    /// **Escape closes the modal, and says it took the keystroke** — so the shell does not ALSO
    /// close the window on the same press.
    ///
    /// The negative leg is the one that matters: a closed modal must report `false`, or Escape on
    /// an ordinary window would stop working entirely.
    #[test]
    fn escape_closes_an_open_modal_and_is_declined_by_a_closed_one() {
        let mut modal = ProfileModal::default();
        assert!(
            !modal.take_escape(),
            "a closed modal swallowed Escape, so the window can no longer be closed with it"
        );

        modal.open(a_profile(true));
        assert!(modal.is_open());
        assert!(modal.take_escape(), "Escape did not reach an open modal");
        assert!(
            !modal.is_open(),
            "Escape was taken and the modal stayed up, which is a surface with no way out"
        );
    }

    /// **The modal is opened on a profile INDEX, and re-opening replaces it.**
    ///
    /// The index rather than a position, because a position names a different profile after a
    /// delete — and this modal has a Save on it.
    #[test]
    fn opening_a_second_profile_replaces_the_first() {
        let mut modal = ProfileModal::default();
        modal.open(a_profile(true));
        modal.open(Editing {
            ix: 7,
            name: "“home”".to_string(),
            active: false,
        });
        assert_eq!(modal.open.as_ref().map(|open| open.ix), Some(7));
    }

    /// **A form taller than the modal can be scrolled, and never past its own ends.**
    ///
    /// The form is painted into rectangles it chooses rather than through egui's layout, so an
    /// `egui::ScrollArea` measures its content as empty and silently offers nothing — which is how
    /// the first version of this modal came to clip its own Save control off the bottom edge.
    ///
    /// # Why the fixture needs a form that does NOT overflow as its control
    ///
    /// Clamping is the property, and it has two ends. A test over overflowing content alone passes
    /// on an implementation that never clamps at the top, and one that clamps everything to zero
    /// passes any assertion that the offset "stays in range". So the same wheel turns are applied
    /// to content that fits, where every one of them must come to nothing.
    #[test]
    fn a_form_taller_than_the_modal_scrolls_and_stops_at_both_ends() {
        let at = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(400.0, 500.0));
        let viewport = at.height() - ACTION_BAND;
        let tall = viewport + 300.0;

        let mut modal = ProfileModal::default();
        modal.open(a_profile(true));

        // Wheeled down, twice, over a form that overflows by 300.
        modal.take_scroll(&wheeled(-200.0, at.center()), at, tall);
        assert!(
            modal.scroll > 0.0,
            "a form taller than the modal did not move, so its lower fields are unreachable"
        );
        modal.take_scroll(&wheeled(-400.0, at.center()), at, tall);
        assert_eq!(
            modal.scroll, 300.0,
            "the form scrolled past its own end, leaving a person looking at empty card"
        );

        // And back up, past the top.
        modal.take_scroll(&wheeled(1_000.0, at.center()), at, tall);
        assert_eq!(
            modal.scroll, 0.0,
            "the form scrolled above its own first field"
        );

        // The control: content that FITS never moves at all, however hard it is wheeled.
        let mut fits = ProfileModal::default();
        fits.open(a_profile(true));
        fits.take_scroll(&wheeled(-500.0, at.center()), at, viewport - 50.0);
        assert_eq!(
            fits.scroll, 0.0,
            "a form that fits was scrolled anyway, so its first field can be hidden by a stray wheel"
        );
    }

    /// **A wheel turn somewhere else in the window does not move the form.**
    ///
    /// The pointer is the only thing that says which surface a wheel is for, and the pane behind the
    /// scrim is still drawn. Without this the form would scroll while somebody was reading the card
    /// underneath it.
    #[test]
    fn a_wheel_turn_outside_the_modal_leaves_the_form_where_it_was() {
        let at = Rect::from_min_size(egui::Pos2::new(100.0, 100.0), Vec2::new(400.0, 500.0));
        let tall = at.height() + 300.0;

        let mut modal = ProfileModal::default();
        modal.open(a_profile(true));
        modal.take_scroll(&wheeled(-300.0, egui::Pos2::new(20.0, 20.0)), at, tall);
        assert_eq!(
            modal.scroll, 0.0,
            "the form scrolled from a wheel turn over the pane behind it"
        );

        // The control: the same turn INSIDE the modal does move it.
        modal.take_scroll(&wheeled(-300.0, at.center()), at, tall);
        assert!(
            modal.scroll > 0.0,
            "no wheel turn moves the form, so the assertion above is empty"
        );
    }

    /// A context reporting one wheel turn of `dy`, with the pointer at `pointer`.
    fn wheeled(dy: f32, pointer: egui::Pos2) -> egui::Context {
        let ctx = egui::Context::default();
        let mut raw = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(1_000.0, 1_000.0),
            )),
            ..Default::default()
        };
        raw.events.push(egui::Event::PointerMoved(pointer));
        raw.events.push(egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Point,
            delta: Vec2::new(0.0, dy),
            modifiers: Default::default(),
        });
        let _ = ctx.run(raw, |_| {});
        ctx
    }

    /// **The title names the profile being edited.**
    ///
    /// Two forms can be alive on the Account tab at once — the creation wizard and this — so a
    /// generic heading would leave a person unsure which profile they are about to spend money on.
    #[test]
    fn the_title_names_the_profile() {
        assert!(title("“work”").contains("“work”"));
        assert_ne!(title("“work”"), title("“home”"));
    }

    /// **A profile this build cannot reach is told which one DIG can, and what to do — never that
    /// the feature is unavailable.**
    ///
    /// The sentence has to name the remedy, because the alternative wording — *not available* —
    /// tells a person to stop looking when a control one surface away would fix it. The remedy it
    /// names is the label the profiles card actually draws.
    #[test]
    fn an_unreachable_profile_is_told_the_remedy_rather_than_that_dig_cannot() {
        let said = unreachable_sentence("“work”");
        let lowered = said.to_lowercase();

        assert!(
            said.contains("“work”"),
            "the sentence never names the profile it is about: {said}"
        );
        assert!(
            lowered.contains("put it in use"),
            "the sentence names no remedy, so a person is told to stop looking: {said}"
        );
        assert!(
            !lowered.contains("not available"),
            "a per-profile limit of THIS BUILD is worded as a missing DIG capability: {said}"
        );
        assert!(
            !lowered.contains("nothing for you to do"),
            "a person with a one-click remedy is told there is nothing they can do: {said}"
        );
    }
}
