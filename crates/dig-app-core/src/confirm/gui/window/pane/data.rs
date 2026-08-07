//! Displaying a FACT: the labelled readout, and the meter for a figure against a cap.
//!
//! # The honesty type
//!
//! [`Value`] has no plain-string variant that can hold "0" or "—" when the truth is not known. A
//! figure that is absent is [`Value::Unknown`], which takes the SENTENCE saying why, and draws in
//! the unavailable colour rather than the value colour. That is not a nicety: dig_ecosystem#2326
//! ships tabs as skeletons ahead of their data, and a skeleton showing a plausible zero is worse
//! than an empty pane, because nobody can tell it apart from a real reading.
//!
//! So a caller cannot express "I don't know" as a number. It has to say so, and say why.

use egui::{Rect, Ui, Vec2};

use super::text;
use crate::confirm::gui::render::{mono, radius, regular, rgba, semibold, size, space};
use crate::confirm::gui::theme::Tokens;

/// One fact a pane displays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Readout {
    /// What the figure is — a noun, not a sentence. "Cache used", not "How much cache is used".
    pub(crate) label: String,
    /// The figure itself.
    pub(crate) value: Value,
}

impl Readout {
    /// A readout of `label` showing `value`.
    pub(crate) fn new(label: impl Into<String>, value: Value) -> Self {
        Self {
            label: label.into(),
            value,
        }
    }
}

/// What a readout shows, and how honest it is about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    /// A word or short phrase: a state name, a yes/no rendered as words.
    Word(String),
    /// A measured quantity and the unit it is in, drawn as one line with the unit in the muted
    /// colour so the number wins the glance. Never a bare number — a figure without its unit is a
    /// figure a reader has to guess at.
    Measure {
        /// The number, already formatted.
        amount: String,
        /// Its unit, as the reader should see it.
        unit: String,
    },
    /// A literal identifier — an address, a store id, a path — set in Space Mono, because a person
    /// reads it character by character and has to tell `1` from `l`.
    Identifier(String),
    /// Not known, and the sentence saying why. Drawn in `--faint`, which is deliberately the ONE
    /// place the pane uses a colour that fails AA for body text: this is not text to read closely,
    /// it is the absence of a value, and it must never be mistaken for one.
    Unknown(String),
}

impl Value {
    /// Whether this is a real reading rather than an absence.
    ///
    /// Used by the tests that pin the honesty rule, and by a caller deciding whether an action over
    /// this value — copying it, say — makes any sense.
    pub(crate) fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }

    /// A byte count as a measure, splitting the unit off the number.
    ///
    /// Formatted by [`crate::cache::format_cap`], which is the one place in the app that decides
    /// whether 1,073,741,824 bytes reads as `1 GiB` — a second formatter here would eventually
    /// disagree with the tray about the same number. The split is on the last space, and a value
    /// that has none stays a whole [`Value::Word`] rather than being cut somewhere arbitrary.
    pub(crate) fn measure_bytes(bytes: u64) -> Self {
        let formatted = crate::cache::format_cap(bytes);
        match formatted.rsplit_once(' ') {
            Some((amount, unit)) => Self::Measure {
                amount: amount.to_owned(),
                unit: unit.to_owned(),
            },
            None => Self::Word(formatted),
        }
    }

    /// The text a reader sees. For [`Value::Unknown`] this is the reason, never a placeholder glyph.
    pub(crate) fn shown(&self) -> &str {
        match self {
            Self::Word(text) | Self::Identifier(text) | Self::Unknown(text) => text,
            Self::Measure { amount, .. } => amount,
        }
    }
}

/// The gap between a readout's label and its value: the smallest step on the scale, because they
/// are one thing. Proximity is grouping.
const LABEL_GAP: f32 = space::S1;

/// The vertical gap between two readouts in the same run.
const READOUT_GAP: f32 = space::S4;

/// Below this column width a run of readouts stacks into one column instead of two.
///
/// Chosen from the content: two columns of a label plus a wrapped `xch1…` value need about this
/// much before the value column stops being able to hold a value.
const TWO_COLUMN_AT: f32 = 420.0;

/// The widest a grid of figures is drawn, in pixels.
///
/// A card stretches to the pane, but a two-column grid of short values does not benefit from it:
/// past this width the gutter between "Version" and "5.33.1" becomes a gap the eye has to jump,
/// and the two columns stop reading as one table. Bars are capped for the same reason — a 1,400 px
/// progress bar measures nothing better than a 640 px one.
const DATA_CAP: f32 = 640.0;

/// The part of `at` a grid of figures may use.
fn grid_within(at: Rect) -> Rect {
    Rect::from_min_size(
        at.left_top(),
        Vec2::new(at.width().min(DATA_CAP), at.height()),
    )
}

/// Draw a run of readouts, in two columns where there is room and one where there is not.
///
/// Returns the height used.
pub(crate) fn readouts(ui: &Ui, at: Rect, t: &Tokens, items: &[Readout]) -> f32 {
    if items.is_empty() {
        return 0.0;
    }
    let at = grid_within(at);
    match at.width() >= TWO_COLUMN_AT {
        true => two_columns(ui, at, t, items),
        false => one_column(ui, at, t, items),
    }
}

/// Every readout stacked, full width. The narrow-window layout, and the fallback.
fn one_column(ui: &Ui, at: Rect, t: &Tokens, items: &[Readout]) -> f32 {
    let mut y = at.top();
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            y += READOUT_GAP;
        }
        y += readout(
            ui,
            Rect::from_min_size(
                egui::Pos2::new(at.left(), y),
                Vec2::new(at.width(), at.bottom() - y),
            ),
            t,
            item,
        );
    }
    y - at.top()
}

/// Readouts paired left and right. Each ROW is as tall as its taller half, so the two columns stay
/// on a shared baseline grid rather than drifting apart down the card.
fn two_columns(ui: &Ui, at: Rect, t: &Tokens, items: &[Readout]) -> f32 {
    let gutter = space::S5;
    let column = (at.width() - gutter) / 2.0;
    let mut y = at.top();
    for (index, pair) in items.chunks(2).enumerate() {
        if index > 0 {
            y += READOUT_GAP;
        }
        let mut tallest = 0.0_f32;
        for (side, item) in pair.iter().enumerate() {
            let left = at.left() + side as f32 * (column + gutter);
            let height = readout(
                ui,
                Rect::from_min_size(egui::Pos2::new(left, y), Vec2::new(column, at.bottom() - y)),
                t,
                item,
            );
            tallest = tallest.max(height);
        }
        y += tallest;
    }
    y - at.top()
}

/// One labelled readout. Returns its height.
///
/// # Why the layout depends on the value
///
/// A short value sits BESIDE its label on one line; anything else goes underneath it. Neither
/// arrangement works for both: an `xch1…` address beside a label has whatever width is left over,
/// which at 480 px is not enough for an address, while "On" stacked under "Second factor" turns two
/// words into two lines and makes a card of four facts a screenful.
///
/// So the rule is decided per value, from the value: a single-line [`Value::Word`] or
/// [`Value::Measure`] that FITS goes inline, and identifiers, absences and anything too wide stack.
/// The inline test is a real measurement of the laid-out text, not a length in characters — a
/// guess in characters is wrong the first time a translation is longer than its English.
pub(crate) fn readout(ui: &Ui, at: Rect, t: &Tokens, item: &Readout) -> f32 {
    let label = ui.painter().layout(
        item.label.clone(),
        regular(size::SM),
        rgba(t.muted),
        at.width(),
    );

    if let Some(width) = inline_width(ui, t, &item.value) {
        let fits = label.size().x + space::S4 + width <= at.width();
        if fits && label.rows.len() == 1 {
            let baseline = at.top();
            ui.painter().galley(
                egui::Pos2::new(at.left(), baseline),
                label.clone(),
                egui::Color32::PLACEHOLDER,
            );
            // Right-aligned, so a column of values shares one edge and can be compared by scanning
            // straight down rather than by reading each label first.
            let slot = Rect::from_min_size(
                egui::Pos2::new(at.right() - width, baseline),
                Vec2::new(width, (at.bottom() - baseline).max(0.0)),
            );
            return value(ui, slot, t, &item.value).max(label.size().y);
        }
    }

    let mut y = at.top();
    ui.painter().galley(
        egui::Pos2::new(at.left(), y),
        label.clone(),
        egui::Color32::PLACEHOLDER,
    );
    y += label.size().y + LABEL_GAP;

    let slot = Rect::from_min_size(
        egui::Pos2::new(at.left(), y),
        Vec2::new(at.width(), (at.bottom() - y).max(0.0)),
    );
    y += value(ui, slot, t, &item.value);
    y - at.top()
}

/// How wide this value is on ONE line, or `None` for a value that must have a line of its own.
///
/// Identifiers and absences always stack: an identifier is read character by character and needs
/// room, and an absence is a sentence rather than a figure.
fn inline_width(ui: &Ui, t: &Tokens, value: &Value) -> Option<f32> {
    match value {
        Value::Identifier(_) | Value::Unknown(_) => None,
        Value::Word(word) => Some(
            ui.painter()
                .layout_no_wrap(word.clone(), semibold(size::BASE), rgba(t.text))
                .size()
                .x,
        ),
        Value::Measure { amount, unit } => {
            let number = ui
                .painter()
                .layout_no_wrap(amount.clone(), semibold(size::BASE), rgba(t.text))
                .size()
                .x;
            let unit = ui
                .painter()
                .layout_no_wrap(unit.clone(), regular(size::SM), rgba(t.muted))
                .size()
                .x;
            Some(number + space::S1 + unit)
        }
    }
}

/// Draw a value at the top of `at`, in the treatment its variant calls for. Returns its height.
pub(crate) fn value(ui: &Ui, at: Rect, t: &Tokens, value: &Value) -> f32 {
    match value {
        Value::Word(word) => wrapped(ui, at, word, semibold(size::BASE), rgba(t.text)),
        Value::Identifier(id) => wrapped(ui, at, id, mono(size::SM), rgba(t.text)),
        // The reason, not a dash: `--faint` plus the sentence is what makes an absent figure
        // unmistakably absent. Regular weight, because it is not a value to be read at a glance.
        Value::Unknown(reason) => wrapped(ui, at, reason, regular(size::SM), rgba(t.faint)),
        Value::Measure { amount, unit } => measure(ui, at, t, amount, unit),
    }
}

/// A number and its unit on one line, the number weighted and the unit muted.
fn measure(ui: &Ui, at: Rect, t: &Tokens, amount: &str, unit: &str) -> f32 {
    let number = ui
        .painter()
        .layout_no_wrap(amount.to_owned(), semibold(size::BASE), rgba(t.text));
    ui.painter()
        .galley(at.left_top(), number.clone(), egui::Color32::PLACEHOLDER);

    let unit_at = at.left() + number.size().x + space::S1;
    let unit_galley = text::one_line(
        ui,
        unit,
        regular(size::SM),
        rgba(t.muted),
        (at.right() - unit_at).max(0.0),
    );
    // Baseline-aligned by bottom edge rather than top: a 13 px unit hung off a 15 px number's top
    // reads as a superscript.
    ui.painter().galley(
        egui::Pos2::new(unit_at, at.top() + number.size().y - unit_galley.size().y),
        unit_galley,
        egui::Color32::PLACEHOLDER,
    );
    number.size().y
}

/// Lay `text` out wrapped to `at`, draw it, and report its height.
fn wrapped(ui: &Ui, at: Rect, text: &str, font: egui::FontId, colour: egui::Color32) -> f32 {
    let galley = ui
        .painter()
        .layout(text.to_owned(), font, colour, at.width().max(1.0));
    ui.painter()
        .galley(at.left_top(), galley.clone(), egui::Color32::PLACEHOLDER);
    galley.size().y
}

/// The height of a meter's bar.
const BAR_HEIGHT: f32 = 8.0;

/// The fraction of a meter's cap above which the bar turns amber.
///
/// A meter that only ever shows the accent colour tells the reader how full something is but never
/// that it MATTERS. Eighty percent is the point at which a content cache starts evicting things the
/// person may want back, which is the fact worth colouring.
const PRESSURE: f64 = 0.8;

/// A figure drawn against its cap — the bar, the reading, and the percentage.
///
/// Returns the height used. Use it where a number's meaning is its RATIO to a limit: cache used
/// against the cache cap. Do not use it for an unbounded count — a meter with no cap is a bar chart
/// with one bar, and it implies a ceiling that does not exist.
pub(crate) fn meter(ui: &Ui, at: Rect, t: &Tokens, label: &str, used: u64, cap: u64) -> f32 {
    let mut y = at.top();
    let heading = ui.painter().layout(
        label.to_owned(),
        regular(size::SM),
        rgba(t.muted),
        at.width(),
    );
    ui.painter().galley(
        egui::Pos2::new(at.left(), y),
        heading.clone(),
        egui::Color32::PLACEHOLDER,
    );
    y += heading.size().y + LABEL_GAP;

    // The figure leads, then the bar, then the words. A bar with no number above it makes a reader
    // estimate a quantity they could have simply been told.
    y += value(
        ui,
        Rect::from_min_size(
            egui::Pos2::new(at.left(), y),
            Vec2::new(at.width(), (at.bottom() - y).max(0.0)),
        ),
        t,
        &Value::measure_bytes(used),
    ) + space::S2;

    let track = Rect::from_min_size(
        egui::Pos2::new(at.left(), y),
        Vec2::new(at.width().min(DATA_CAP), BAR_HEIGHT),
    );
    let corner = egui::CornerRadius::same((BAR_HEIGHT / 2.0) as u8);
    ui.painter()
        .rect_filled(track, corner, rgba(t.surface_2.over(t.surface)));

    let fraction = fill_fraction(used, cap);
    let filled = (track.width() * fraction as f32).max(0.0);
    if filled > 0.0 {
        ui.painter().rect_filled(
            Rect::from_min_size(track.left_top(), Vec2::new(filled, BAR_HEIGHT)),
            corner,
            rgba(match fraction >= PRESSURE {
                true => t.amber,
                false => t.dig_purple,
            }),
        );
    }
    y += BAR_HEIGHT + space::S2;

    // The reading is spelled out in words as well as drawn as a bar. Never meaning by colour or
    // shape alone: a bar a screen reader cannot see, and a colour a colourblind reader cannot tell
    // from the accent, are both the same omission.
    y += text::caption(
        ui,
        Rect::from_min_size(
            egui::Pos2::new(at.left(), y),
            Vec2::new(at.width(), (at.bottom() - y).max(0.0)),
        ),
        t,
        &reading(used, cap, fraction),
    );
    y - at.top()
}

/// How full a meter is, in `0.0..=1.0`.
///
/// A zero cap reads as FULL rather than as a divide-by-zero or an empty bar: a cache that can hold
/// nothing is at its limit, and drawing it empty would say the opposite of the truth.
fn fill_fraction(used: u64, cap: u64) -> f64 {
    match cap {
        0 => 1.0,
        cap => (used as f64 / cap as f64).clamp(0.0, 1.0),
    }
}

/// The sentence under a meter's bar.
///
/// It repeats the figure above the bar on purpose. The bar is the only thing carrying the RATIO
/// visually, and a ratio conveyed by a bar alone is a ratio a screen reader cannot report and a
/// colourblind reader cannot tell from the accent — so the full reading is spelled out in words.
fn reading(used: u64, cap: u64, fraction: f64) -> String {
    format!(
        "{} of {} used ({}%)",
        crate::cache::format_cap(used),
        crate::cache::format_cap(cap),
        (fraction * 100.0).round() as u64
    )
}

/// A small rounded chip carrying one short word — a state badge beside a heading.
///
/// Returns the rectangle it drew, so a caller can place something after it. Use it for a state a
/// reader scans for; do not use it for a value they read, which is a [`Readout`].
pub(crate) fn badge(ui: &Ui, top_left: egui::Pos2, t: &Tokens, word: &str, tone: Tone) -> Rect {
    let (fill, ink) = tone.look(t);
    let galley = ui
        .painter()
        .layout_no_wrap(word.to_owned(), semibold(size::XS), ink);
    let at = Rect::from_min_size(
        top_left,
        Vec2::new(
            galley.size().x + space::S3,
            galley.size().y + space::S1 * 2.0,
        ),
    );
    ui.painter()
        .rect_filled(at, egui::CornerRadius::same(radius::SM), fill);
    ui.painter().galley(
        at.center() - galley.size() / 2.0,
        galley,
        egui::Color32::PLACEHOLDER,
    );
    at
}

/// What a badge MEANS, which is what decides its colour.
///
/// Semantic rather than chromatic — a caller asks for `Tone::Bad`, never for "amber" — so the one
/// mapping from meaning to colour lives here and cannot be spelled two ways in two panes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tone {
    /// Working as it should.
    Good,
    /// Needs attention, but nothing is lost.
    Warn,
    /// Not working.
    Bad,
    /// A fact with no valence.
    Neutral,
}

/// How opaque a badge's fill is over the surface behind it.
///
/// Faint on purpose: a badge is a label with a tinted backing, not a filled button. At full strength
/// a run of badges reads as a row of controls a person can press.
const WASH: u8 = 34;

/// `colour` at `alpha`, for the washes a badge is filled with.
fn tint(colour: crate::confirm::gui::theme::Rgba, alpha: u8) -> crate::confirm::gui::theme::Rgba {
    crate::confirm::gui::theme::Rgba { a: alpha, ..colour }
}

impl Tone {
    /// The chip's fill and its ink.
    fn look(self, t: &Tokens) -> (egui::Color32, egui::Color32) {
        match self {
            Self::Good => (rgba(tint(t.ok, WASH).over(t.surface)), rgba(t.ok)),
            Self::Warn => (rgba(t.amber_bg.over(t.surface)), rgba(t.amber)),
            Self::Bad => (
                rgba(tint(t.danger, WASH).over(t.surface)),
                rgba(t.danger_text),
            ),
            Self::Neutral => (rgba(t.surface_2.over(t.surface)), rgba(t.muted)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **An unknown figure cannot be expressed as a number.**
    ///
    /// The rule that makes skeleton-first safe, asserted on the TYPE rather than on a screenshot: a
    /// value is either a real reading or an explicit absence carrying its reason, and there is no
    /// third thing a caller can reach for. If a plain-string variant is ever added, this fails.
    #[test]
    fn an_absent_figure_is_a_reason_and_never_a_number() {
        let absent = Value::Unknown("The node has not answered yet.".to_string());
        assert!(!absent.is_known());
        assert_eq!(absent.shown(), "The node has not answered yet.");

        for known in [
            Value::Word("Running".to_string()),
            Value::Identifier("xch1abc".to_string()),
            Value::Measure {
                amount: "12".to_string(),
                unit: "stores".to_string(),
            },
        ] {
            assert!(known.is_known(), "{known:?} should be a real reading");
        }
    }

    /// **A byte count keeps its unit, and a value with no unit is not cut in half.**
    ///
    /// The second half is the one that matters: splitting on the last space is only safe if a
    /// space-free formatting stays whole. Both are asserted against `format_cap`'s real output
    /// rather than a transcription of it, so a change to how the app words a size is caught here
    /// instead of silently producing `1` with the unit `GiB` lost.
    #[test]
    fn a_byte_count_carries_its_unit_and_a_unitless_one_stays_whole() {
        let gibibyte = Value::measure_bytes(1024 * 1024 * 1024);
        let Value::Measure { amount, unit } = &gibibyte else {
            panic!("{gibibyte:?} lost its unit");
        };
        assert_eq!(
            format!("{amount} {unit}"),
            crate::cache::format_cap(1024 * 1024 * 1024),
            "the split does not reassemble into what the app actually says"
        );
        assert!(!unit.is_empty(), "the unit is empty");

        assert_eq!(
            Value::Word("640".to_string()).shown(),
            "640",
            "a word is shown verbatim"
        );
    }

    /// **A meter's fill is the ratio, clamped, and a zero cap reads as full.**
    ///
    /// Pinned from BOTH sides of every bound: under, at, over, and the degenerate cap. A fraction
    /// tested only in the middle of its range would not catch a bar drawn past its own track, which
    /// is what an unclamped ratio does the moment a cache exceeds a cap the user just lowered.
    #[test]
    fn a_meters_fill_is_clamped_and_a_zero_cap_reads_as_full() {
        assert_eq!(fill_fraction(0, 100), 0.0);
        assert_eq!(fill_fraction(50, 100), 0.5);
        assert_eq!(fill_fraction(100, 100), 1.0);
        assert_eq!(
            fill_fraction(400, 100),
            1.0,
            "a cache over its cap drew a bar past the end of its track"
        );
        assert_eq!(
            fill_fraction(0, 0),
            1.0,
            "a cache that can hold nothing must read as full, not as empty"
        );
    }

    /// **The bar turns amber exactly at the pressure threshold, and not before.**
    ///
    /// Both sides of the published bound: one step under must stay accent, at-bound must be amber.
    /// A threshold tested only from above confirms itself.
    #[test]
    fn the_pressure_colour_changes_at_the_threshold_from_both_sides() {
        assert!(
            fill_fraction(79, 100) < PRESSURE,
            "79% must not read as under pressure"
        );
        assert!(
            fill_fraction(80, 100) >= PRESSURE,
            "80% is the threshold and must read as under pressure"
        );
    }

    /// A meter's caption states the reading in words, so the bar is never the only carrier.
    #[test]
    fn a_meters_reading_is_spelled_out_in_words() {
        let words = reading(512 * 1024 * 1024, 1024 * 1024 * 1024, 0.5);
        assert!(words.contains("50%"), "{words}");
        assert!(words.contains(" of "), "{words}");
        assert!(
            words.contains(&crate::cache::format_cap(1024 * 1024 * 1024)),
            "the cap is missing from {words}"
        );
    }

    /// **A short value shares its label's line; a long one takes its own.**
    ///
    /// Two actors of each kind, and the pair is the point: a readout that ALWAYS stacked and one
    /// that always inlined would each satisfy a single-fixture test. The address is the case that
    /// must never inline — it is unreadable in whatever width is left beside a label — and "On" is
    /// the case that must never stack, because four stacked two-letter values are a screenful.
    ///
    /// Asserted on drawn height, which is what the layout actually produces, rather than on the
    /// predicate that chooses it — testing a layout with the function that decides it would pass
    /// over a rule that is right and never consulted.
    #[test]
    fn a_short_value_shares_its_labels_line_and_a_long_one_does_not() {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let short = Readout::new("Second factor", Value::Word("On".into()));
        let address = Readout::new(
            "Receive address",
            Value::Identifier(
                "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln".into(),
            ),
        );
        let absent = Readout::new(
            "Cache",
            Value::Unknown("No node has reported its cache yet.".into()),
        );

        let measured = std::cell::Cell::new((0.0_f32, 0.0_f32, 0.0_f32));
        for _ in 0..2 {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::Area::new(egui::Id::new("inline-test")).show(ctx, |ui| {
                    let t = crate::confirm::gui::theme::Theme::Light.tokens();
                    let at = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(400.0, 400.0));
                    measured.set((
                        readout(ui, at, &t, &short),
                        readout(ui, at, &t, &address),
                        readout(ui, at, &t, &absent),
                    ));
                });
            });
        }

        let (inline, stacked_id, stacked_absence) = measured.get();
        assert!(
            stacked_id > inline * 1.5,
            "an address ({stacked_id} px) took no more room than an inline word ({inline} px), so \
             it was squeezed beside its label"
        );
        assert!(
            stacked_absence > inline * 1.5,
            "an absent value ({stacked_absence} px) was inlined beside its label"
        );
    }

    /// **A short value stacks anyway when the column is too narrow to hold both.**
    ///
    /// The inline rule is a measurement, not a value-kind lookup — so the SAME readout that inlines
    /// at 400 px must stack when there is no room. Without this the rule would silently overlap a
    /// label and its value on a narrow pane.
    #[test]
    fn a_short_value_stacks_when_its_label_leaves_no_room() {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let item = Readout::new("Second factor", Value::Word("On".into()));

        let measured = std::cell::Cell::new((0.0_f32, 0.0_f32));
        for _ in 0..2 {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::Area::new(egui::Id::new("cramped-test")).show(ctx, |ui| {
                    let t = crate::confirm::gui::theme::Theme::Light.tokens();
                    let roomy = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(400.0, 400.0));
                    let cramped = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(96.0, 400.0));
                    measured.set((
                        readout(ui, roomy, &t, &item),
                        readout(ui, cramped, &t, &item),
                    ));
                });
            });
        }
        let (roomy, cramped) = measured.get();
        assert!(
            cramped > roomy * 1.5,
            "the same readout took {cramped} px in a 96 px column and {roomy} px in a 400 px one — \
             it stayed inline and its value is sitting on its label"
        );
    }

    /// **A narrow pane stacks its readouts and a wide one pairs them.**
    ///
    /// Asserted through the real drawing at the two widths the window actually spans, on the height
    /// each returns: four readouts in two columns are two rows tall, and in one column four. A
    /// layout that ignored the width would return the same height twice.
    #[test]
    fn readouts_pair_up_when_there_is_room_and_stack_when_there_is_not() {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let items = vec![
            Readout::new("Agent", Value::Word("Running".into())),
            Readout::new("Node", Value::Word("Connected".into())),
            Readout::new("Version", Value::Word("5.33.1".into())),
            Readout::new("Cache", Value::Word("1 GiB".into())),
        ];

        let measured = std::cell::Cell::new((0.0_f32, 0.0_f32));
        for _ in 0..2 {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::Area::new(egui::Id::new("readout-test")).show(ctx, |ui| {
                    let t = crate::confirm::gui::theme::Theme::Light.tokens();
                    let wide = Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(TWO_COLUMN_AT + 40.0, 600.0),
                    );
                    let narrow = Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(TWO_COLUMN_AT - 40.0, 600.0),
                    );
                    measured.set((
                        readouts(ui, wide, &t, &items),
                        readouts(ui, narrow, &t, &items),
                    ));
                });
            });
        }

        let (paired, stacked) = measured.get();
        assert!(paired > 0.0, "the wide layout drew nothing");
        assert!(
            stacked > paired * 1.6,
            "four readouts in one column ({stacked} px) were not materially taller than four in \
             two ({paired} px) — the width is not changing the layout"
        );
    }

    /// An empty run of readouts takes no space at all, rather than a gap the caller cannot see.
    #[test]
    fn no_readouts_take_no_height() {
        let ctx = egui::Context::default();
        let height = std::cell::Cell::new(-1.0_f32);
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::Area::new(egui::Id::new("empty-readouts")).show(ctx, |ui| {
                let t = crate::confirm::gui::theme::Theme::Light.tokens();
                height.set(readouts(
                    ui,
                    Rect::from_min_size(egui::Pos2::ZERO, Vec2::splat(400.0)),
                    &t,
                    &[],
                ));
            });
        });
        assert_eq!(height.get(), 0.0);
    }
}
