//! Aligned columns for a run of rows that are the SAME kind of thing (dig_ecosystem#334).
//!
//! # Why this is not [`super::data::rows`]
//!
//! [`super::data`] draws FACTS: a label and the one value it names. Its two-column mode pairs
//! unrelated readouts left and right — a version beside an uptime — and its one-column mode stacks
//! them. Neither aligns anything ACROSS rows, because a readout's value is right-aligned to the
//! card's edge and a readout's label is whatever prose it carries. That is right for a grid of
//! facts and wrong for a list a person scans down: somebody asking *do I hold enough free $DIG*
//! compares the same field in twenty rows, and a field that starts at a different x in every row
//! cannot be compared without reading each row as prose.
//!
//! So this module owns exactly one thing the data module does not: POSITION. Every cell is still
//! drawn by [`super::data::value`], in the treatment its [`Value`] variant earns — the mono
//! identifier, the faint absence with its reason, the weighted word. A second cell renderer here
//! would be the third rendering of a value in one pane tree.
//!
//! # The full-width cell, and why the widest column is not a column
//!
//! A row may carry a value [`beneath`](Row::beneath) its aligned cells, spanning the whole width.
//! It exists for one shape of data: a value too wide to share a line with anything. A 64-character
//! hex coin id set in Space Mono is about 450 px on its own, which is most of the 480 px window, so
//! an inline column for it could only be made to fit by cutting it — and a truncation this app
//! performed would be a claim this app made about which coin it is. Given the choice between a
//! narrower table and a shortened identifier, this takes the narrower table.
//!
//! A row is therefore at most two lines tall: the aligned cells, then the spanning value. That is
//! the same height as the label-over-value readout it replaces, which is what keeps the ten-row
//! budget in [`super::wallet_coins`] intact.

use egui::{Rect, Ui, Vec2};

use super::data::{self, Value};
use super::text;
use crate::confirm::gui::render::space;
use crate::confirm::gui::theme::Tokens;

/// One column: its heading, and the share of the table's width it takes.
///
/// A SHARE rather than a pixel width, because the window resizes and a fixed column is either too
/// narrow for its content at 480 px or a lake of empty space at 1,400 px. Shares are normalised, so
/// they may be written as any set of proportions that reads clearly at the call site.
pub(crate) struct Column {
    /// What the column holds, as a noun. Drawn once, above the rows.
    pub(crate) heading: &'static str,
    /// This column's portion of the width, relative to the other columns'.
    pub(crate) share: f32,
}

/// One row of a table: a cell per column, and an optional value spanning all of them beneath.
pub(crate) struct Row {
    /// One entry per [`Column`], in the same order.
    ///
    /// `None` is an EMPTY cell and draws nothing. It means the column does not apply to this row,
    /// which a caller may only say when the column's absence is itself the honest reading — never
    /// as a stand-in for a value nobody measured. That distinction is why this is `Option<Value>`
    /// and not a `Value` with an empty string: [`Value::Unknown`] exists to carry an unmeasured
    /// field, and it draws its reason rather than nothing at all.
    pub(crate) cells: Vec<Option<Value>>,
    /// A value drawn full width under the cells — an identifier too wide to be a column.
    pub(crate) beneath: Option<Value>,
}

/// The gap between two columns.
const GUTTER: f32 = space::S3;

/// The vertical gap between two rows.
const ROW_GAP: f32 = space::S4;

/// The gap between a row's aligned cells and the value spanning beneath them.
///
/// The smallest step on the scale, matching the label-to-value gap in [`super::data`]: the spanning
/// value belongs to the row above it, and proximity is what says so.
const BENEATH_GAP: f32 = space::S1;

/// The widest a table is drawn, in pixels.
///
/// The same cap [`super::data`] puts on a grid of figures, for the same reason: past it the gutter
/// between two columns becomes a gap the eye has to jump, and the columns stop reading as one
/// table.
const TABLE_CAP: f32 = 640.0;

/// Draw a table of `rows` under `columns`. Returns the height used.
///
/// An empty `rows` draws NOTHING, headings included. A heading row over no rows is a table
/// promising columns of data that are not there, and a caller with nothing to show has a sentence
/// to say instead — which is the caller's to choose, because the reason a list is empty is the
/// caller's fact and not this module's.
pub(crate) fn table(ui: &mut Ui, at: Rect, t: &Tokens, columns: &[Column], rows: &[Row]) -> f32 {
    if rows.is_empty() || columns.is_empty() {
        return 0.0;
    }
    let at = Rect::from_min_size(
        at.left_top(),
        Vec2::new(at.width().min(TABLE_CAP), at.height()),
    );
    let widths = column_widths(at.width(), columns);

    let mut y = at.top();
    let mut tallest_heading = 0.0_f32;
    for (index, column) in columns.iter().enumerate() {
        let slot = cell_rect(at, &widths, index, y);
        tallest_heading = tallest_heading.max(text::caption(ui, slot, t, column.heading));
    }
    y += tallest_heading + space::S2;

    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            y += ROW_GAP;
        }
        let mut tallest = 0.0_f32;
        for (column, cell) in row.cells.iter().enumerate().take(widths.len()) {
            if let Some(cell) = cell {
                let slot = cell_rect(at, &widths, column, y);
                tallest = tallest.max(data::value(ui, slot, t, cell));
            }
        }
        y += tallest;
        if let Some(beneath) = &row.beneath {
            y += BENEATH_GAP;
            let slot = Rect::from_min_size(
                egui::Pos2::new(at.left(), y),
                Vec2::new(at.width(), (at.bottom() - y).max(0.0)),
            );
            y += data::value(ui, slot, t, beneath);
        }
    }
    y - at.top()
}

/// Each column's width in pixels, from its share of what the gutters leave.
pub(crate) fn column_widths(width: f32, columns: &[Column]) -> Vec<f32> {
    let gutters = GUTTER * columns.len().saturating_sub(1) as f32;
    let usable = (width - gutters).max(0.0);
    let total: f32 = columns.iter().map(|column| column.share.max(0.0)).sum();
    // An all-zero set of shares would divide by zero and lay every column on top of the first, so
    // it falls back to equal columns rather than to a stack of overlapping text.
    if total <= 0.0 {
        return vec![usable / columns.len() as f32; columns.len()];
    }
    columns
        .iter()
        .map(|column| usable * column.share.max(0.0) / total)
        .collect()
}

/// The rectangle column `index` occupies, from `y` down.
fn cell_rect(at: Rect, widths: &[f32], index: usize, y: f32) -> Rect {
    let left = at.left()
        + widths[..index]
            .iter()
            .map(|width| width + GUTTER)
            .sum::<f32>();
    Rect::from_min_size(
        egui::Pos2::new(left, y),
        Vec2::new(widths[index], (at.bottom() - y).max(0.0)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Columns are laid out left to right without overlapping, and they fill the width.**
    ///
    /// The property that makes a column scannable: cell `n + 1` starts after cell `n` ends, in
    /// every row, at any width. A layout that let two columns overlap would draw two values on top
    /// of each other, which on a money surface is a third number nobody holds.
    #[test]
    fn columns_are_laid_out_in_order_and_fill_the_width() {
        let columns = [
            Column {
                heading: "a",
                share: 1.0,
            },
            Column {
                heading: "b",
                share: 2.0,
            },
            Column {
                heading: "c",
                share: 1.0,
            },
        ];
        let widths = column_widths(400.0, &columns);

        assert_eq!(widths.len(), 3);
        assert!(
            widths[1] > widths[0],
            "a column with twice the share is wider: {widths:?}"
        );
        let spent: f32 = widths.iter().sum::<f32>() + GUTTER * 2.0;
        assert!(
            (spent - 400.0).abs() < 0.01,
            "the columns and their gutters spend the whole width: {spent}"
        );
        assert!(
            widths.iter().all(|width| *width > 0.0),
            "no column is collapsed to nothing: {widths:?}"
        );
    }

    /// **A width too small for the gutters collapses to zero-width columns rather than to negative
    /// ones**, which would lay each column to the LEFT of the one before it.
    #[test]
    fn an_impossibly_narrow_table_does_not_invert_its_columns() {
        let columns = [
            Column {
                heading: "a",
                share: 1.0,
            },
            Column {
                heading: "b",
                share: 1.0,
            },
        ];
        let widths = column_widths(1.0, &columns);
        assert!(
            widths.iter().all(|width| *width >= 0.0),
            "{widths:?} contains a negative column"
        );
    }
}
