//! Drawing the brand — the primitives every prompt window is built from.
//!
//! hub.dig.net's look is CSS: gradients, quiet radii, a hairline card. egui has
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

/// How strongly Close's hover wash tints the bar with `--danger`.
///
/// A TINT, not the accent itself: a solid red field behind a cross announces the destruction louder
/// than the act deserves on a window that can simply be reopened, and it would drop the glyph's
/// contrast below AA. This is the same weight `--dig-wash` carries for the other three.
const CLOSE_HOVER_ALPHA: u8 = 28;

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

/// The DIG Mark, as the brand actually draws it (dig_ecosystem#3007).
///
/// # Why the artwork and not a shape that resembles it
///
/// This used to be a rounded square filled with the accent gradient — a stand-in that read as *a
/// purple thing* rather than as DIG. The brand has a mark, it is already in this crate ([`MARK`],
/// the same file the window icon and the tray take), and `professional-ui`'s reuse-before-invent
/// rule exists for exactly this case: a surface approximating art the brand already owns is how one
/// product comes to show two different logos.
///
/// The gradient remains as the FALLBACK, for the same reason the tray decode is fallible: a corrupt
/// asset should cost the header its picture and nothing else. A blank square where a logo belongs
/// reads as a failed load; the gradient reads as the brand, quietly.
pub fn brand_mark(ui: &Ui, rect: Rect, t: &Tokens) {
    let Some(mark) = mark_texture(ui.ctx()) else {
        gradient_fill(ui, rect, 6.0, rgba(t.dig_purple), rgba(t.dig_magenta));
        return;
    };
    ui.painter().image(
        mark.id(),
        rect,
        Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
        Color32::WHITE,
    );
}

/// The DIG Mark's own artwork, embedded so no surface reads it from disk.
///
/// One copy for the whole crate: the header, the window icon and the tray all take this, so they
/// cannot drift into showing different marks (dig_ecosystem#2340 is what happens when a surface has
/// no mark at all; two marks would be worse).
pub const MARK: &[u8] = include_bytes!("../../../assets/mark-64.png");

/// Decode [`MARK`] into `(rgba, width, height)`, or `None` if it will not decode.
///
/// **Fallible on purpose.** Every caller here is a picture, and a picture is never worth a panic in
/// a process that also carries a person's consent surface.
pub fn decode_mark() -> Option<(Vec<u8>, u32, u32)> {
    let mut reader = png::Decoder::new(MARK).read_info().ok()?;
    let info = reader.info();
    // Only the one shape the checked-in asset has. A PNG in another colour type or bit depth would
    // need resampling, and silently mis-decoding a brand mark is worse than showing no mark.
    if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
        return None;
    }
    let (width, height) = (info.width, info.height);
    let mut rgba = vec![0; reader.output_buffer_size()];
    let frame = reader.next_frame(&mut rgba).ok()?;
    rgba.truncate(frame.buffer_size());
    Some((rgba, width, height))
}

/// The mark uploaded to the GPU once, and handed back on every later frame.
///
/// Cached in the context's own store rather than re-uploaded per frame: the mark is drawn on every
/// frame of every window, and a texture upload per frame is a cost paid sixty times a second for an
/// image that never changes.
fn mark_texture(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let key = egui::Id::new("dig-brand-mark-texture");
    if let Some(cached) = ctx.data(|d| d.get_temp::<egui::TextureHandle>(key)) {
        return Some(cached);
    }
    let (rgba, width, height) = decode_mark()?;
    let image = egui::ColorImage::from_rgba_unmultiplied([width as usize, height as usize], &rgba);
    let handle = ctx.load_texture("dig-brand-mark", image, egui::TextureOptions::LINEAR);
    ctx.data_mut(|d| d.insert_temp(key, handle.clone()));
    Some(handle)
}

/// A button in hub's language, returning its click [`Response`].
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

/// A button's fixed height, and the number every pane control is sized against.
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

/// How wide a button has to be for `label`.
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

/// Paint a button's face into `rect`, in hub's language.
///
/// Split out of [`button`] so the window's absolutely-positioned pane buttons and the prompt's
/// allocated ones are the SAME control. Two functions each drawing "a DIG button" is how a product
/// ends up with two button styles, which is precisely the failure dig_ecosystem#2326 exists to fix.
///
/// # The register: a product surface, not a front door (dig_ecosystem#2354)
///
/// A button is a flat fill at [`radius::SM`], with **no glow and no gradient**. It used to carry
/// both, which is dig.net's register — the dark cosmic neon where a bloom marks the one hero call to
/// action on a landing page. dig-app is a local utility, and every one of its panes had a glowing
/// pill, so the bloom stopped meaning *this is the important one* and became background texture. It
/// was also actively harmful twice over: the halo painted OUTSIDE the control's own rect and visibly
/// overlapped the button beneath it at 480 px, and the destructive weight carried the same bloom as
/// the affirmative, so a destroy shone exactly as invitingly as a save.
///
/// What still separates the weights is what always should have: hue and fill. Purple affirms, red
/// destroys, a bordered ghost recedes. The accent GRADIENT survives in exactly one place —
/// [`brand_mark`] — because a brand flourish belongs on the mark and nowhere else.
///
/// Focus is unaffected and is now the only thing that paints outside `rect`: the 2 px accent ring.
/// That is a strengthening rather than a loss. #2038 removed an accent halo from the destroy prompt
/// precisely because it read as the focus ring; with no halo at all, the ring is unambiguous.
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
    // The same radius the inputs and the chooser take, so a control group holding a button beside a
    // dropdown is one shape rather than two. Clamped to the height for the degenerate rects layout
    // produces transiently.
    let corner = radius::SM.min((rect.height() / 2.0) as u8);

    match fill {
        Some((base, hover)) if disabled => {
            let _ = hover;
            ui.painter()
                .rect_filled(rect, CornerRadius::same(corner), rgba(base));
        }
        Some((base, hover)) => {
            let from = if hovered { hover } else { base };
            ui.painter()
                .rect_filled(rect, CornerRadius::same(corner), rgba(from));
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

/// Horizontal padding inside a button — hub's `.btn { padding: 12px 26px }`, doubled for both sides.
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

/// Which glyph a window control draws (dig_ecosystem#2997).
///
/// A closed enum, not a character: the glyphs are STROKED, so nothing here depends on a font
/// shipping a symbol, and the four shapes are the four things this chrome can do. A general icon
/// system is deliberately not what this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowIcon {
    /// A single horizontal bar, low in the box — the universal minimise.
    Minimize,
    /// An empty square — grow to fill the screen.
    Maximize,
    /// Two offset squares — come back out of maximised.
    Restore,
    /// A cross.
    Close,
}

/// The side of the square every window glyph is drawn inside (dig_ecosystem#3007).
///
/// A SQUARE, and the same square for all four, rather than the slot inset by a margin. The slot is
/// 40 x 30, so insetting it produced a 22 x 12 *landscape* box: the minimise bar came out nearly
/// twice the width of the maximise square it sits beside, and the close cross was a squashed X. One
/// optical box is what makes the row read as a set.
///
/// 10 px is the mark size Windows 11 and macOS both settle near, and it leaves the hit area the full
/// slot — the target stays comfortably clickable (`professional-ui`) even though the mark is small.
const GLYPH_BOX: f32 = 10.0;

/// The glyph's own box inside a control slot: [`GLYPH_BOX`] square, centred, on whole pixels.
///
/// Snapped because a 1 px stroke on a half pixel is drawn as two grey rows rather than one dark one.
/// That is the entire difference between a crisp mark and a smudged one at this size, and it is the
/// half of "cleaner" no amount of colour tuning can supply.
fn glyph_box(slot: Rect) -> Rect {
    let centre = Pos2::new(slot.center().x.round(), slot.center().y.round());
    Rect::from_center_size(centre, Vec2::splat(GLYPH_BOX))
}

/// The id a window control senses under, derived from its NAME.
///
/// Exposed so a caller — and a test — can reach a control by the same word a screen reader
/// announces, instead of by hunting for painted text. An icon paints no text at all, so a harness
/// that looked for words would find nothing and a chrome test would stop reaching its control while
/// still passing.
pub fn window_control_id(name: &str) -> egui::Id {
    egui::Id::new(("dig-app-window-control", name))
}

/// A window-chrome control drawn as a WORD, in a rectangle the caller placed (dig_ecosystem#3007).
///
/// The text twin of [`window_control`], and deliberately the same contract: it senses under
/// [`window_control_id`], carries the same name to assistive technology and to the test harness, and
/// takes the same hover wash. So the chrome has one control vocabulary rather than two, and a test
/// reaches `Unlock…` exactly the way it reaches `Close`.
///
/// It draws a word because it is not a window verb. Minimise, maximise and close are universal
/// glyphs a person already knows; an invented lock glyph would be a guess, and the one control here
/// that ACTS ON THE PERSON'S ACCOUNT is the last one that should be a rebus.
pub fn chrome_word_control(ui: &mut Ui, rect: Rect, name: &str, t: &Tokens) -> Response {
    let response = ui
        .interact(rect, window_control_id(name), Sense::click())
        .on_hover_text(name);
    response
        .widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, ui.is_enabled(), name));

    let hovered = response.hovered();
    if hovered {
        ui.painter().rect_filled(
            rect,
            CornerRadius::same(radius::SM),
            rgba(t.dig_wash.over(t.surface)),
        );
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    let ink = match hovered {
        true => t.dig_purple,
        false => t.muted,
    };
    let galley = ui
        .painter()
        .layout_no_wrap(name.to_owned(), semibold(size::XS), rgba(ink));
    ui.painter().galley(
        rect.center() - galley.size() / 2.0,
        galley,
        Color32::PLACEHOLDER,
    );
    response
}

/// How wide a slot [`chrome_word_control`] needs for `name`.
///
/// Measured from the text the control will actually draw, in the font it will actually draw it in,
/// for the reason [`super::window::shell::ChromeSlots`] states: a control whose label outgrows its
/// slot still draws and still senses — on top of its neighbour.
pub fn chrome_word_width(ui: &Ui, name: &str, t: &Tokens) -> f32 {
    ui.painter()
        .layout_no_wrap(name.to_owned(), semibold(size::XS), rgba(t.muted))
        .size()
        .x
        + CHROME_WORD_PAD
}

/// The breathing room on each side of a chrome word control's text, doubled into its width.
const CHROME_WORD_PAD: f32 = 20.0;

/// A window-chrome control drawn as a stroked glyph, with an accessible NAME.
///
/// # The name is not decoration
///
/// An icon-only control is unreachable by assistive technology and unaddressable by a test harness
/// unless it carries a name, which `professional-ui` states explicitly. The name is supplied here
/// three ways at once: as the widget's accessibility label, as its tooltip on hover, and as the
/// widget id — so a screen reader, a person hovering, and a test all learn the same word, and the
/// word cannot drift between them because there is only one of it.
///
/// The chrome drew words before this (dig_ecosystem#2569's fix for a window with no controls at
/// all). Turning them into glyphs must not take anything away: all four controls survive, at the
/// same or larger hit area, and only their MARK changed.
pub fn window_control(
    ui: &mut Ui,
    rect: Rect,
    icon: WindowIcon,
    name: &str,
    t: &Tokens,
) -> Response {
    let response = ui
        .interact(rect, window_control_id(name), Sense::click())
        .on_hover_text(name);
    response
        .widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, ui.is_enabled(), name));

    if response.hovered() {
        // Close hovers DANGEROUS, the other three hover neutral. Closing is the one irreversible
        // thing this row does, and every desktop platform says so in red — a person who lands on it
        // by accident on the way to Maximize gets a warning before the click, not after.
        let wash = match icon {
            WindowIcon::Close => Rgba {
                a: CLOSE_HOVER_ALPHA,
                ..t.danger
            }
            .over(t.surface),
            _ => t.dig_wash.over(t.surface),
        };
        ui.painter()
            .rect_filled(rect, CornerRadius::same(radius::SM), rgba(wash));
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }

    // `--muted` at rest for the same reason a text control's label takes it: this is the control's
    // content, and it carries the 4.5:1 bar rather than the 3:1 one a mere border would (#2038). On
    // hover it goes to `--text`, so the mark under the pointer is the darkest one in the row.
    let ink = match (response.hovered(), icon) {
        (true, WindowIcon::Close) => t.danger_text,
        (true, _) => t.text,
        (false, _) => t.muted,
    };
    let stroke = Stroke::new(1.0_f32, rgba(ink));
    let box_ = glyph_box(rect);
    let painter = ui.painter();
    match icon {
        WindowIcon::Minimize => {
            painter.hline(box_.left()..=box_.right(), box_.bottom(), stroke);
        }
        WindowIcon::Maximize => {
            painter.rect_stroke(box_, CornerRadius::ZERO, stroke, StrokeKind::Inside);
        }
        WindowIcon::Restore => {
            let back = Rect::from_min_max(
                Pos2::new(box_.left() + 3.0, box_.top()),
                Pos2::new(box_.right(), box_.bottom() - 3.0),
            );
            let front = Rect::from_min_max(
                Pos2::new(box_.left(), box_.top() + 3.0),
                Pos2::new(box_.right() - 3.0, box_.bottom()),
            );
            painter.rect_stroke(back, CornerRadius::ZERO, stroke, StrokeKind::Inside);
            painter.rect_filled(front, CornerRadius::ZERO, rgba(t.surface));
            painter.rect_stroke(front, CornerRadius::ZERO, stroke, StrokeKind::Inside);
        }
        WindowIcon::Close => {
            painter.line_segment([box_.left_top(), box_.right_bottom()], stroke);
            painter.line_segment([box_.right_top(), box_.left_bottom()], stroke);
        }
    }
    response
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

    /// Every shape a closure paints, flattened out of the frame it painted them into.
    ///
    /// Two frames, as everywhere else in this crate's paint tests: the first builds the font atlas
    /// and the second lays out against it, so a measurement is never taken against a missing glyph.
    fn painted(draw: impl Fn(&Ui, &Tokens)) -> Vec<Shape> {
        let ctx = egui::Context::default();
        crate::confirm::gui::window::install_fonts(&ctx);
        let t = crate::confirm::gui::theme::Theme::Light.tokens();
        let screen = Rect::from_min_size(Pos2::ZERO, Vec2::splat(400.0));

        let mut output = egui::FullOutput::default();
        for _ in 0..2 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("paint-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| draw(ui, &t));
                },
            );
        }

        fn walk(shape: &Shape, out: &mut Vec<Shape>) {
            match shape {
                Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, out)),
                other => out.push(other.clone()),
            }
        }
        let mut shapes = Vec::new();
        for clipped in &output.shapes {
            walk(&clipped.shape, &mut shapes);
        }
        shapes
    }

    /// The rect a shape covers, ignoring text (whose galley is centred inside the control anyway).
    fn covered(shape: &Shape) -> Option<Rect> {
        match shape {
            Shape::Rect(r) => Some(r.rect),
            Shape::Mesh(mesh) => Some(mesh.calc_bounds()),
            _ => None,
        }
    }

    /// **A button paints inside its own rect: no bloom, and no gradient (dig_ecosystem#2354).**
    ///
    /// The property is that the control occupies the space it was given. The glow this replaces
    /// painted four widening copies OUTSIDE `rect`, which at 480 px visibly overlapped the button
    /// beneath it in `settings-dark-480.png` — so geometry, not colour, is what is asserted, because
    /// geometry is what the defect actually was.
    ///
    /// Run over BOTH filled weights. `Danger` is not incidental: the halo followed the control's own
    /// colour, so a fix that removed only the accent bloom would leave a destroy glowing red and
    /// would pass a Primary-only test. `Ghost` is excluded and covered by the focus case below —
    /// it never had a fill to bloom, so it cannot tell a fixed implementation from a broken one.
    #[test]
    fn a_button_paints_no_bloom_and_no_gradient_outside_its_own_rect() {
        let rect = Rect::from_min_size(Pos2::new(100.0, 100.0), Vec2::new(180.0, BUTTON_HEIGHT));
        for weight in [Weight::Primary, Weight::Danger] {
            let shapes = painted(|ui, t| {
                button_face(
                    ui,
                    rect,
                    "Turn auto-update off",
                    weight,
                    Enablement::Live {
                        hovered: false,
                        focused: false,
                    },
                    t,
                );
            });
            assert!(
                shapes.iter().any(|s| matches!(s, Shape::Rect(_))),
                "{weight:?} painted no fill at all, so this test is looking at an empty frame"
            );
            for shape in &shapes {
                assert!(
                    !matches!(shape, Shape::Mesh(_)),
                    "{weight:?} still paints a gradient mesh; the accent gradient belongs to the \
                     DIG mark alone"
                );
                if let Some(area) = covered(shape) {
                    assert!(
                        rect.expand(0.5).contains_rect(area),
                        "{weight:?} painted {area:?}, outside its own {rect:?} — a bloom that \
                         overlaps whatever is drawn beneath it"
                    );
                }
            }
        }
    }

    /// **Focus still paints its ring outside the control — the one thing that may.**
    ///
    /// The control for the test above, and the property #2038 depends on: a person has to be able to
    /// SEE which button Enter will press. A "fix" that clipped every button to its rect would pass
    /// the bloom test and silently delete the focus ring.
    #[test]
    fn a_focused_button_still_draws_its_ring_beyond_its_rect() {
        let rect = Rect::from_min_size(Pos2::new(100.0, 100.0), Vec2::new(180.0, BUTTON_HEIGHT));
        let shapes = painted(|ui, t| {
            button_face(
                ui,
                rect,
                "Unlock…",
                Weight::Ghost,
                Enablement::Live {
                    hovered: false,
                    focused: true,
                },
                t,
            );
        });
        assert!(
            shapes
                .iter()
                .filter_map(covered)
                .any(|area| !rect.expand(0.5).contains_rect(area)),
            "a focused control drew nothing beyond its own edge, so its ring is gone"
        );
    }

    /// **Every window glyph is drawn in the SAME square, on whole pixels** (dig_ecosystem#3007).
    ///
    /// What "cleaner" came to concretely. The glyphs used to be the slot inset by a margin, and the
    /// slot is 40 x 30 — so the minimise bar was 22 px wide against a 12 px maximise square, and
    /// the row read as three unrelated marks rather than a set. The box is now square and shared,
    /// so the four marks are the same size whatever the slot around them becomes.
    ///
    /// The snapping half is asserted too, because it is the half a screenshot shows and a colour
    /// test cannot: a 1 px stroke centred on a half pixel is drawn as two grey rows instead of one
    /// dark one, which is exactly what a smudged titlebar glyph is.
    #[test]
    fn every_window_glyph_shares_one_square_pixel_aligned_box() {
        // Two slots, differing in BOTH parity and size, so a box that merely inherited its slot
        // would come out different in each and cannot pass by coincidence.
        for slot in [
            Rect::from_min_size(Pos2::new(100.0, 7.0), Vec2::new(40.0, 30.0)),
            Rect::from_min_size(Pos2::new(100.5, 7.5), Vec2::new(41.0, 29.0)),
        ] {
            let box_ = glyph_box(slot);
            assert_eq!(
                box_.width(),
                box_.height(),
                "the glyph box is not square in {slot:?}"
            );
            assert_eq!(box_.width(), GLYPH_BOX);
            assert!(
                box_.center().x.fract() == 0.0 && box_.center().y.fract() == 0.0,
                "the glyph box at {box_:?} is centred off the pixel grid, so its strokes blur"
            );
            assert!(
                slot.contains_rect(box_),
                "the glyph box {box_:?} escaped its slot {slot:?}"
            );
        }
    }

    /// **Close warns before it is pressed, and the other controls do not** (dig_ecosystem#3007).
    ///
    /// Closing is the one irreversible thing the row does. Asserted as a DIFFERENCE between the
    /// hovered close and the hovered minimise rather than as "close paints something": a wash both
    /// controls share is not a warning, it is a hover state, and a test looking at close alone
    /// cannot tell those apart.
    #[test]
    fn only_close_warns_when_it_is_hovered() {
        let hovered = |icon| {
            let ctx = egui::Context::default();
            let t = super::super::theme::Theme::Light.tokens();
            let rect = Rect::from_min_size(Pos2::new(10.0, 10.0), Vec2::new(40.0, 30.0));
            let mut output = egui::FullOutput::default();
            for _ in 0..4 {
                output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::splat(200.0))),
                        events: vec![egui::Event::PointerMoved(rect.center())],
                        ..Default::default()
                    },
                    |ctx| {
                        egui::Area::new(egui::Id::new("glyph-test")).show(ctx, |ui| {
                            window_control(ui, rect, icon, "Probe", &t);
                        });
                    },
                );
            }
            fn fills(shape: &egui::Shape, out: &mut Vec<Color32>) {
                match shape {
                    Shape::Rect(rect) => out.push(rect.fill),
                    Shape::Vec(shapes) => shapes.iter().for_each(|s| fills(s, out)),
                    _ => {}
                }
            }
            let mut found = Vec::new();
            for clipped in &output.shapes {
                fills(&clipped.shape, &mut found);
            }
            found
        };

        let close = hovered(WindowIcon::Close);
        let minimize = hovered(WindowIcon::Minimize);
        assert!(
            !close.is_empty() && !minimize.is_empty(),
            "neither control painted a hover wash, so this compares nothing"
        );
        assert_ne!(
            close, minimize,
            "close and minimize hover identically, so the warning on the irreversible one is absent"
        );
    }

    /// **The header draws the brand's OWN mark, not a shape that resembles it**
    /// (dig_ecosystem#3007).
    ///
    /// Asserted as an image, because that is the difference the change is about: a gradient square
    /// and the real artwork are both "purple ink in a 20 px box", and any test that measured colour
    /// or extent would pass on the placeholder this replaced.
    #[test]
    fn the_brand_mark_draws_the_real_artwork() {
        let shapes = painted(|ui, t| {
            brand_mark(
                ui,
                Rect::from_min_size(Pos2::new(20.0, 20.0), Vec2::splat(24.0)),
                t,
            );
        });
        // A TEXTURED mesh specifically. `gradient_fill` also emits a `Shape::Mesh` — on the DEFAULT
        // texture — so "any mesh" is a property the placeholder had too, and a test asserting it
        // would have passed unchanged on the square this replaces.
        assert!(
            shapes.iter().any(|s| match s {
                Shape::Mesh(mesh) => mesh.texture_id != egui::TextureId::default(),
                _ => false,
            }),
            "the mark painted no textured mesh, so it is drawing a stand-in rather than the artwork"
        );
    }

    /// **The embedded mark is the real 64 px artwork, and it is not blank.**
    ///
    /// The control for the test above: an image shape proves the header asked for a texture, and
    /// this proves the texture it asked for carries a picture. A fully transparent PNG would satisfy
    /// the drawing test exactly while showing the person nothing at all.
    #[test]
    fn the_embedded_mark_decodes_to_visible_artwork() {
        let (rgba, width, height) = decode_mark().expect("the checked-in DIG Mark did not decode");
        assert_eq!(
            (width, height),
            (64, 64),
            "the mark is not the 64 px source"
        );
        assert_eq!(rgba.len(), 64 * 64 * 4);
        let opaque = rgba.chunks_exact(4).filter(|px| px[3] > 0).count();
        assert!(
            opaque > 64 * 64 / 10,
            "only {opaque} of {} pixels carry any ink, so the mark is effectively blank",
            64 * 64
        );
    }

    /// **The gradient the mark falls back to still paints something.**
    ///
    /// [`brand_mark`]'s fallback cannot be reached from a test — the asset decodes — so the fallback
    /// is exercised directly rather than left as a branch nobody has ever seen run.
    #[test]
    fn the_gradient_fallback_still_paints() {
        let shapes = painted(|ui, t| {
            gradient_fill(
                ui,
                Rect::from_min_size(Pos2::ZERO, Vec2::splat(20.0)),
                6.0,
                rgba(t.dig_purple),
                rgba(t.dig_magenta),
            );
        });
        assert!(shapes.iter().any(|s| matches!(s, Shape::Mesh(_))));
    }

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
