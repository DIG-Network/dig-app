//! The vertical cursor every pane block is placed through.
//!
//! # Why a cursor and not egui's layout
//!
//! The window paints into absolute rectangles — the sidebar, the strip and the pane are split from
//! one body rect, and the shell reads those rects back in its tests. A block therefore needs to know
//! the column it may use and where the last block stopped, which is exactly the two numbers a
//! [`Flow`] carries. Blocks stay free functions of `(ui, rect)` and remain measurable on their own;
//! the flow only decides where the next one starts.
//!
//! # Blocks measure themselves
//!
//! Every block is handed a full-width rectangle whose TOP is the cursor and whose height is the
//! remaining column, and returns the height it actually used. Nothing in this system reserves a
//! guessed height for content it has not laid out — that is how a wrapped label ends up overlapping
//! the thing below it at 480 px, which is the width this window can legitimately be dragged to.

use egui::{Rect, Ui, Vec2};

/// A top-to-bottom cursor over a pane's content column.
pub(crate) struct Flow<'ui> {
    ui: &'ui mut Ui,
    column: Rect,
    y: f32,
    live: bool,
}

impl<'ui> Flow<'ui> {
    /// Start at the top of `column`.
    ///
    /// `live` is false while a prompt is up: blocks still DRAW — a pane that emptied itself behind a
    /// prompt would read as broken rather than busy — but nothing senses a click.
    pub(crate) fn new(ui: &'ui mut Ui, column: Rect, live: bool) -> Self {
        let y = column.top();
        Self {
            ui,
            column,
            y,
            live,
        }
    }

    /// Whether controls may be clicked right now.
    pub(crate) fn live(&self) -> bool {
        self.live
    }

    /// Where the next block will start.
    pub(crate) fn cursor(&self) -> f32 {
        self.y
    }

    /// Whether the column is full, so a caller can stop composing rather than draw off the bottom.
    ///
    /// The pane clamps rather than scrolls: a half-drawn control hanging off the bottom edge is a
    /// control nobody can tell is unreachable.
    pub(crate) fn exhausted(&self) -> bool {
        self.y >= self.column.bottom()
    }

    /// Advance without drawing — the gap between two blocks.
    pub(crate) fn gap(&mut self, gap: f32) {
        self.y += gap;
    }

    /// Place one block, and advance past whatever it drew.
    ///
    /// Returns the block's own result, or `None` when the column was already full — so a caller can
    /// tell "it drew nothing" apart from "there was nowhere to draw it".
    pub(crate) fn place<R>(&mut self, block: impl FnOnce(&mut Ui, Rect) -> (f32, R)) -> Option<R> {
        if self.exhausted() {
            return None;
        }
        let at = self.slot();
        let (height, result) = block(self.ui, at);
        self.y += height;
        Some(result)
    }

    /// The rectangle the next block may use: full width, from the cursor to the bottom.
    fn slot(&self) -> Rect {
        Rect::from_min_size(
            egui::Pos2::new(self.column.left(), self.y),
            Vec2::new(
                self.column.width(),
                (self.column.bottom() - self.y).max(0.0),
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A column 100 px tall starting at (0, 0), and a flow over it.
    fn flow_over(ui: &mut Ui, height: f32) -> Flow<'_> {
        Flow::new(
            ui,
            Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(200.0, height)),
            true,
        )
    }

    /// Run `body` inside a real egui frame, so a flow has a genuine `Ui` to place blocks into.
    ///
    /// `FnMut` rather than `FnOnce` because `Context::run` may call its closure more than once; the
    /// body is written to be idempotent, and taking it by `FnOnce` would not compile against that.
    fn in_a_frame(mut body: impl FnMut(&mut Ui)) {
        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::Area::new(egui::Id::new("flow-test")).show(ctx, |ui| body(ui));
        });
    }

    /// **A block's own measured height decides where the next one starts.**
    ///
    /// The property that makes wrapping safe: nothing reserves a guessed height. Asserted with two
    /// blocks of DIFFERENT heights, because a flow that advanced by a constant would agree with a
    /// single-block fixture exactly.
    #[test]
    fn each_block_starts_where_the_previous_one_measured_itself_to_end() {
        in_a_frame(|ui| {
            let mut flow = flow_over(ui, 400.0);
            let first = flow.place(|_, at| (30.0, at.top())).expect("room");
            let second = flow.place(|_, at| (70.0, at.top())).expect("room");
            let third = flow.place(|_, at| (0.0, at.top())).expect("room");

            assert_eq!(first, 0.0);
            assert_eq!(second, 30.0, "the second block ignored the first's height");
            assert_eq!(
                third, 100.0,
                "the third block ignored the second's DIFFERENT height"
            );
        });
    }

    /// **A full column refuses further blocks instead of drawing off its bottom edge.**
    ///
    /// The fixture puts the cursor past the bottom with a block that is honestly that tall, rather
    /// than by constructing a zero-height column — a zero-height column is exhausted before the
    /// first block, which would not distinguish "stops when full" from "never starts".
    #[test]
    fn a_full_column_stops_accepting_blocks() {
        in_a_frame(|ui| {
            let mut flow = flow_over(ui, 100.0);
            assert!(!flow.exhausted(), "an empty column is not full");
            assert_eq!(flow.place(|_, _| (140.0, 1_u8)), Some(1), "the first fits");
            assert!(flow.exhausted());
            assert_eq!(
                flow.place(|_, _| (10.0, 2_u8)),
                None,
                "a block was placed below the bottom of the column"
            );
        });
    }

    /// A block's slot is the full column width and never extends past the bottom.
    #[test]
    fn a_slot_spans_the_column_and_stops_at_its_bottom() {
        in_a_frame(|ui| {
            let mut flow = flow_over(ui, 100.0);
            flow.gap(60.0);
            let slot = flow.place(|_, at| (0.0, at)).expect("room");
            assert_eq!(slot.width(), 200.0);
            assert_eq!(slot.top(), 60.0);
            assert_eq!(slot.bottom(), 100.0, "the slot overran the column");
        });
    }
}
