//! Drawing the brand — the primitives every prompt window is built from.
//!
//! hub.dig.net's look is CSS: gradients, pill radii, soft accent glows, a hairline card. egui has
//! rounded rects, strokes and meshes. This module is the translation layer, written ONCE so that no
//! widget anywhere re-derives a gradient or invents a corner radius, and so the whole visual
//! language can be re-tuned in one file when hub's changes.
//!
//! Everything here takes [`Tokens`], never a literal colour — see [`super::theme`] for why that rule
//! is what keeps a second copy of a design system diffable against its source.

use egui::{
    Color32, CornerRadius, Mesh, Pos2, Rect, Response, Sense, Shape, Stroke, StrokeKind, Ui, Vec2,
};

use super::render::{radius, regular, rgba, semibold, size, Weight};
use super::theme::{Rgba, Tokens};

/// Blend two colours by `t` in `0.0..=1.0`.
fn lerp(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let f = |x: u8, y: u8| (f32::from(x) + (f32::from(y) - f32::from(x)) * t).round() as u8;
    Color32::from_rgb(f(a.r(), b.r()), f(a.g(), b.g()), f(a.b(), b.b()))
}

/// How many segments each rounded corner is approximated with.
///
/// Eight is where the corner stops reading as a polygon at the radii hub uses (8–24 px) on a 2× DPI
/// display; more is invisible and costs vertices on every frame.
const CORNER_SEGMENTS: usize = 8;

/// The outline of a rounded rectangle, as points, clockwise from the bottom-right corner.
fn rounded_outline(rect: Rect, radius: f32) -> Vec<Pos2> {
    let r = radius
        .min(rect.width() / 2.0)
        .min(rect.height() / 2.0)
        .max(0.0);
    let quarter = std::f32::consts::FRAC_PI_2;
    let corners = [
        (rect.right_bottom() + Vec2::new(-r, -r), 0.0_f32),
        (rect.left_bottom() + Vec2::new(r, -r), quarter),
        (rect.left_top() + Vec2::new(r, r), quarter * 2.0),
        (rect.right_top() + Vec2::new(-r, r), quarter * 3.0),
    ];
    let mut pts = Vec::with_capacity(corners.len() * (CORNER_SEGMENTS + 1));
    for (centre, start) in corners {
        for step in 0..=CORNER_SEGMENTS {
            let angle = start + quarter * (step as f32 / CORNER_SEGMENTS as f32);
            pts.push(centre + Vec2::new(r * angle.cos(), r * angle.sin()));
        }
    }
    pts
}

/// Fill a rounded rect with a left-to-right linear gradient — hub's `linear-gradient(115deg, …)`.
///
/// egui has no gradient fill, so this is a triangle fan over the rounded outline with the colour
/// interpolated per vertex. Written once here; every accented surface in the app calls it.
pub fn gradient_fill(ui: &Ui, rect: Rect, radius: f32, from: Color32, to: Color32) {
    let pts = rounded_outline(rect, radius);
    let mut mesh = Mesh::default();
    let width = rect.width().max(1.0);
    mesh.colored_vertex(rect.center(), lerp(from, to, 0.5));
    for p in &pts {
        mesh.colored_vertex(*p, lerp(from, to, (p.x - rect.left()) / width));
    }
    let n = pts.len() as u32;
    for i in 0..n {
        mesh.add_triangle(0, 1 + i, 1 + (i + 1) % n);
    }
    ui.painter().add(Shape::mesh(mesh));
}

/// The accent glow behind a primary control — hub's `--glow-color` under a `box-shadow`.
///
/// Four widening translucent copies rather than a real blur: egui has no blur pass, and at these
/// radii the stack is indistinguishable from one while costing four rects instead of a render target.
fn glow(ui: &Ui, rect: Rect, corner: u8, colour: Rgba) {
    for (grow, scale) in [(2.0_f32, 0.9), (5.0, 0.55), (9.0, 0.32), (14.0, 0.18)] {
        let alpha = (f32::from(colour.a) * scale) as u8;
        ui.painter().rect_filled(
            rect.expand(grow).translate(Vec2::new(0.0, grow * 0.25)),
            CornerRadius::same(corner.saturating_add(grow as u8)),
            Color32::from_rgba_unmultiplied(colour.r, colour.g, colour.b, alpha),
        );
    }
}

/// The window card: hub's `--surface` with `--border`, `--radius-lg` and `--shadow-pop`.
///
/// Drawn edge to edge and OPAQUE. hub fakes its drop shadow by letting the page show through a
/// transparent gap; a transparent frameless surface on Windows loses its content on any move or
/// restore and never recomposites (#2038), so the shadow is drawn inside the window instead and the
/// surface stays opaque. A prompt that can go invisible is worse than one without a soft edge.
pub fn card(ui: &Ui, rect: Rect, t: &Tokens) {
    ui.painter().add(
        egui::epaint::Shadow {
            offset: [0, 8],
            blur: 28,
            spread: 0,
            color: rgba(t.shadow),
        }
        .as_shape(rect, CornerRadius::same(radius::LG)),
    );
    ui.painter()
        .rect_filled(rect, CornerRadius::same(radius::LG), rgba(t.surface));
    ui.painter().rect_stroke(
        rect,
        CornerRadius::same(radius::LG),
        Stroke::new(1.0_f32, rgba(t.border)),
        StrokeKind::Inside,
    );
}

/// A recessed panel — hub's `--surface-2` inside `--border`. Holds the decoded transaction.
pub fn panel(ui: &Ui, rect: Rect, t: &Tokens) {
    ui.painter()
        .rect_filled(rect, CornerRadius::same(radius::BASE), rgba(t.surface_2));
    ui.painter().rect_stroke(
        rect,
        CornerRadius::same(radius::BASE),
        Stroke::new(1.0_f32, rgba(t.border)),
        StrokeKind::Inside,
    );
}

/// A warning panel — hub's `--amber-bg` inside `--amber-border`. Holds an irreversible-loss body.
pub fn warning_panel(ui: &Ui, rect: Rect, t: &Tokens) {
    let bg = t.amber_bg.over(t.surface);
    ui.painter()
        .rect_filled(rect, CornerRadius::same(radius::BASE), rgba(bg));
    ui.painter().rect_stroke(
        rect,
        CornerRadius::same(radius::BASE),
        Stroke::new(1.0_f32, rgba(t.amber_border.over(bg))),
        StrokeKind::Inside,
    );
}

/// A scannable QR code, drawn on a WHITE field whatever the theme.
///
/// The field is white and the modules are black in both themes, deliberately: a camera reads
/// contrast, and a dark-theme QR in `--surface` on `--text` is a QR a phone will refuse. The white
/// card is the quiet zone the format requires, so it is part of the code, not decoration.
///
/// Returns the square it drew, so the caller can advance past it.
pub fn qr(ui: &Ui, top_left: Pos2, available: f32, art: &crate::confirm::QrArt) -> Rect {
    let module = art.module_pixels(available as i32).max(1);
    let side = art.drawn_pixels(module);
    let field = Rect::from_min_size(top_left, Vec2::splat(side as f32));
    ui.painter()
        .rect_filled(field, CornerRadius::same(radius::SM), Color32::WHITE);
    for (column, row) in art.dark_modules() {
        let origin = top_left
            + Vec2::new(
                (column as i32 * module) as f32,
                (row as i32 * module) as f32,
            );
        ui.painter().rect_filled(
            Rect::from_min_size(origin, Vec2::splat(module as f32)),
            CornerRadius::ZERO,
            Color32::BLACK,
        );
    }
    field
}

/// The DIG mark: hub's accent gradient in a small rounded square.
pub fn brand_mark(ui: &Ui, rect: Rect, t: &Tokens) {
    gradient_fill(ui, rect, 6.0, rgba(t.dig_purple), rgba(t.dig_magenta));
}

/// A pill button in hub's language, returning its click [`Response`].
///
/// `focused` draws the keyboard focus ring. The ring is a visible 2 px accent outline rather than a
/// subtle tint, because on the destroy window the focused control is the thing standing between a
/// stray Enter and a destroyed master seed — the user has to be able to SEE which one it is.
pub fn button(ui: &mut Ui, label: &str, weight: Weight, focused: bool, t: &Tokens) -> Response {
    let height = BUTTON_HEIGHT;
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(button_width(ui, label), height), Sense::click());
    button_face(
        ui,
        rect,
        label,
        weight,
        Enablement::Live {
            hovered: response.hovered(),
            focused,
        },
        t,
    );
    response
}

/// A pill button's fixed height, and the number every pane control is sized against.
pub const BUTTON_HEIGHT: f32 = 40.0;

/// The same button, placed in a rectangle the CALLER chose and identified by an id it controls.
///
/// # Why this exists beside [`button`]
///
/// [`button`] allocates through egui's layout, which also derives the widget's id from that layout.
/// A content pane positions absolutely and needs ids that survive a rebuild — its rows are addressed
/// by `(label, occurrence)` precisely so a click cannot resolve to nothing after the surface
/// regenerates (dig_ecosystem#2074). Those two requirements are incompatible with `button`'s
/// signature and with nothing else about it, so the FACE is shared ([`button_face`]) and only the
/// allocation differs. A second button-drawing function would be a second button style.
pub fn button_at(
    ui: &mut Ui,
    rect: Rect,
    id: egui::Id,
    label: &str,
    weight: Weight,
    enabled: bool,
    t: &Tokens,
) -> Response {
    // A disabled control still senses HOVER, so it can carry an explanation, but never a click: it
    // is not clickable, rather than clickable-and-ignored.
    let sense = match enabled {
        true => Sense::click(),
        false => Sense::hover(),
    };
    let response = ui.interact(rect, id, sense);
    let state = match enabled {
        true => Enablement::Live {
            hovered: response.hovered(),
            focused: response.has_focus(),
        },
        false => Enablement::Disabled,
    };
    button_face(ui, rect, label, weight, state, t);
    response
}

/// How wide a pill button has to be for `label`.
///
/// Exposed so a caller laying buttons out itself — a content pane places them absolutely rather than
/// through egui's layout — can wrap a row before it runs off the edge instead of after.
pub fn button_width(ui: &Ui, label: &str) -> f32 {
    ui.painter()
        .layout_no_wrap(label.to_owned(), semibold(size::BUTTON), Color32::WHITE)
        .size()
        .x
        + space_x()
}

/// Whether a button can be pressed right now, and what the pointer and keyboard are doing to it.
///
/// One enum rather than three booleans because the states are not independent: a control that cannot
/// be pressed cannot be hovered or focused either, and a `hovered: true, enabled: false` combination
/// would be a look nobody designed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enablement {
    /// Pressable.
    Live {
        /// The pointer is over it.
        hovered: bool,
        /// It holds keyboard focus, and takes the accent ring.
        focused: bool,
    },
    /// Not pressable. Drawn dimmed and flat — never hidden, because the label carries the remedy.
    Disabled,
}

/// Paint a pill button's face into `rect`, in hub's language.
///
/// Split out of [`button`] so the window's absolutely-positioned pane buttons and the prompt's
/// allocated ones are the SAME control. Two functions each drawing "a DIG button" is how a product
/// ends up with two button styles, which is precisely the failure dig_ecosystem#2326 exists to fix.
pub fn button_face(
    ui: &Ui,
    rect: Rect,
    label: &str,
    weight: Weight,
    state: Enablement,
    t: &Tokens,
) {
    let disabled = state == Enablement::Disabled;
    let (hovered, focused) = match state {
        Enablement::Live { hovered, focused } => (hovered, focused),
        Enablement::Disabled => (false, false),
    };

    let fill = match (weight, disabled) {
        // A dimmed accent, not a grey slab: the control keeps its shape so the eye still reads it as
        // the primary action of the pane, and only its availability changed.
        (_, true) => Some((t.surface_2, t.surface_2)),
        (Weight::Primary, false) => Some((t.dig_purple, t.dig_purple_hover)),
        (Weight::Danger, false) => Some((t.danger, t.danger)),
        (Weight::Ghost, false) => None,
    };
    let text_colour = match (weight, disabled) {
        (_, true) => rgba(t.faint),
        (Weight::Primary | Weight::Danger, false) => Color32::WHITE,
        (Weight::Ghost, false) => rgba(t.muted),
    };
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), semibold(size::BUTTON), text_colour);
    let corner = radius::PILL.min((rect.height() / 2.0) as u8);

    match fill {
        Some((base, hover)) if disabled => {
            let _ = hover;
            ui.painter()
                .rect_filled(rect, CornerRadius::same(corner), rgba(base));
        }
        Some((base, hover)) => {
            // The glow follows the control's OWN colour. An accent glow behind a destructive button
            // reads as the focus ring — which is drawn in the accent — so a destroy window appeared
            // to have both controls focused at once, and the one that looked brightest was the one
            // that destroys the account (#2038, found in the screenshot gallery). The pre-focused
            // refusal (dig_ecosystem#1799) is only a safeguard if the user can SEE which control
            // Enter will press.
            let halo = match weight {
                Weight::Danger => Rgba {
                    a: t.glow.a,
                    ..t.danger
                },
                _ => t.glow,
            };
            glow(ui, rect, corner, halo);
            let from = if hovered { hover } else { base };
            // The affirmative carries hub's accent GRADIENT; the destructive is a flat `--danger`,
            // so the two are told apart by more than hue at a glance.
            match weight {
                Weight::Primary => {
                    gradient_fill(ui, rect, f32::from(corner), rgba(from), rgba(t.dig_magenta))
                }
                _ => {
                    ui.painter()
                        .rect_filled(rect, CornerRadius::same(corner), rgba(from));
                }
            }
        }
        None => {
            let edge = if hovered { t.border_strong } else { t.border };
            ui.painter().rect_stroke(
                rect,
                CornerRadius::same(corner),
                Stroke::new(1.0_f32, rgba(edge)),
                StrokeKind::Inside,
            );
        }
    }

    if focused {
        ui.painter().rect_stroke(
            rect.expand(3.0),
            CornerRadius::same(corner.saturating_add(3)),
            Stroke::new(2.0_f32, rgba(t.dig_purple)),
            StrokeKind::Outside,
        );
    }

    ui.painter().galley(
        rect.center() - galley.size() / 2.0,
        galley,
        Color32::PLACEHOLDER,
    );
    if hovered {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
}

/// Horizontal padding inside a pill — hub's `.btn { padding: 12px 26px }`, doubled for both sides.
fn space_x() -> f32 {
    52.0
}

/// The padding a text control puts around its label to make an honest hit area.
const CONTROL_PAD: Vec2 = Vec2::new(18.0, 10.0);

/// Where a text control's label sits inside that padding.
enum ControlAlign {
    /// Centred in the hit area — for a control positioned by its own slot, like the chrome toggle.
    Centred,
    /// Flush with the hit area's left edge — for a control sitting in a column of left-aligned text,
    /// where centring would indent it out of line with everything above it.
    Column,
}

/// A small text control: a label, a generous hit area, and a wash on hover.
///
/// A text control rather than an icon because it must be legible to a screen reader and
/// unambiguous without colour, and because an unlabelled sun/moon glyph is one more thing a user has
/// to decode on a window that is asking them to authorise a spend.
fn text_control(ui: &mut Ui, label: &str, t: &Tokens, align: ControlAlign) -> Response {
    let galley = ui
        .painter()
        // `--muted`, not `--faint`: this is an interactive control's LABEL, so it takes AA's 4.5:1
        // text bar. `--faint` is 3.34:1 on white (#2038).
        .layout_no_wrap(label.to_owned(), regular(size::SM), rgba(t.muted));
    let (rect, response) = ui.allocate_exact_size(galley.size() + CONTROL_PAD, Sense::click());
    if response.hovered() {
        ui.painter().rect_filled(
            rect,
            CornerRadius::same(radius::SM),
            rgba(t.dig_wash.over(t.surface)),
        );
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    let pos = match align {
        ControlAlign::Centred => rect.center() - galley.size() / 2.0,
        ControlAlign::Column => {
            egui::Pos2::new(rect.left(), rect.center().y - galley.size().y / 2.0)
        }
    };
    ui.painter().galley(pos, galley, Color32::PLACEHOLDER);
    response
}

/// The theme toggle in the window chrome: a small, always-reachable text control.
pub fn theme_toggle(ui: &mut Ui, label: &str, t: &Tokens) -> Response {
    text_control(ui, label, t, ControlAlign::Centred)
}

/// A text control sitting INSIDE the body's text column — the reveal-while-typing switch.
///
/// Left-aligned rather than centred so its label starts on the same x as the field label and the
/// field above it. Centring indents it by half the hit-area padding, which reads as a stray
/// half-indent in an otherwise flush column (#2038, caught in the gallery).
pub fn inline_toggle(ui: &mut Ui, label: &str, t: &Tokens) -> Response {
    text_control(ui, label, t, ControlAlign::Column)
}

/// A hairline rule across `rect`'s width at `y` — hub's `--border`.
pub fn rule(ui: &Ui, rect: Rect, y: f32, t: &Tokens) {
    ui.painter().hline(
        rect.left()..=rect.right(),
        y,
        Stroke::new(1.0_f32, rgba(t.border)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The outline closes and stays inside its rect — a corner that bulged past the edge would show
    /// as a notch against the card behind it.
    #[test]
    fn a_rounded_outline_stays_within_its_rect() {
        let rect = Rect::from_min_size(Pos2::new(10.0, 20.0), Vec2::new(200.0, 40.0));
        let pts = rounded_outline(rect, 12.0);
        assert_eq!(pts.len(), 4 * (CORNER_SEGMENTS + 1));
        for p in pts {
            assert!(rect.expand(0.01).contains(p), "{p:?} escaped {rect:?}");
        }
    }

    /// A radius larger than the control clamps to a capsule instead of inverting the corners.
    #[test]
    fn an_oversized_radius_clamps_instead_of_inverting() {
        let rect = Rect::from_min_size(Pos2::ZERO, Vec2::new(40.0, 20.0));
        for p in rounded_outline(rect, 999.0) {
            assert!(rect.expand(0.01).contains(p), "{p:?}");
        }
    }

    /// A zero-size control must not produce NaN vertices — it happens transiently during layout.
    #[test]
    fn a_degenerate_rect_produces_finite_points() {
        for p in rounded_outline(Rect::from_min_size(Pos2::ZERO, Vec2::ZERO), 8.0) {
            assert!(p.x.is_finite() && p.y.is_finite(), "{p:?}");
        }
    }

    #[test]
    fn lerp_hits_both_ends_and_the_middle() {
        let (a, b) = (Color32::BLACK, Color32::WHITE);
        assert_eq!(lerp(a, b, 0.0), a);
        assert_eq!(lerp(a, b, 1.0), b);
        assert_eq!(lerp(a, b, 0.5).r(), 128);
        // Out-of-range t clamps rather than wrapping to a wrong colour.
        assert_eq!(lerp(a, b, -3.0), a);
        assert_eq!(lerp(a, b, 3.0), b);
    }
}
