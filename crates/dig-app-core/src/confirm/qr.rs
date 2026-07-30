//! A QR code as a **window element** — the square of modules a native window paints
//! (dig_ecosystem#1849).
//!
//! # Why the encoder lives here and not with the thing being encoded
//!
//! The two-factor enrolment flow ([`crate::account::second_factor`]) knows what an `otpauth://` URI
//! is; it has no business knowing what a finder pattern is. A QR is a way of DRAWING a string, so it
//! belongs beside the window that draws it, in the one module every platform backend already reads. It
//! also means exactly one place in this crate depends on the encoder, which is what makes the
//! supply-chain claim in the workspace manifest checkable rather than aspirational.
//!
//! # Why a matrix of modules and not a bitmap
//!
//! Every DIG window scales from design units at the display's DPI (dig_ecosystem#1832), and a bitmap
//! chosen at one size is a postage stamp at 250% and a blurred mess anywhere it is stretched. A matrix
//! of true/false modules has no size at all until the window multiplies it by a whole number of pixels
//! per module, which is the only way a QR both fills its allotted space and keeps the crisp edges a
//! camera needs. See [`QrArt::module_pixels`].
//!
//! # Secret handling
//!
//! The provisioning URI carries the TOTP secret in the clear, so the MODULES DO TOO — a photograph of
//! this square is the credential. The matrix is therefore held in a [`Zeroizing`] buffer and wiped when
//! the window that drew it goes away. Nothing here logs, and [`Debug`] is written by hand so the
//! pattern cannot reach a panic message.
//!
//! The honest limit: [`qrcodegen`] allocates its own working buffers, and a third-party crate's
//! temporaries are not reachable from here. Wiping OUR copy bounds how long the pattern is guaranteed
//! to sit in this process's heap; it does not make the encode itself scrubbing.

use zeroize::Zeroizing;

/// The error-correction level the enrolment QR is encoded at.
///
/// `Medium` (~15% recoverable) rather than `Low`: this code is read off a GLOWING SCREEN by a
/// hand-held camera, through reflections, at an angle, and often while the screen is being
/// photographed rather than scanned live. `Low` produces a smaller symbol that scans worse in exactly
/// those conditions, and `High` would inflate the module count enough to shrink each module below what
/// a phone camera resolves at arm's length — the failure this ticket exists to prevent.
const ERROR_CORRECTION: qrcodegen::QrCodeEcc = qrcodegen::QrCodeEcc::Medium;

/// The QUIET ZONE, in modules, on every side.
///
/// Four is the ISO/IEC 18004 minimum, and it is not decorative: a QR with no margin against the
/// surrounding window chrome is one most decoders refuse outright, because the finder patterns are
/// located by their contrast against clear space. Reserved by [`QrArt::total_modules`] so the window's
/// layout cannot forget it.
const QUIET_MODULES: usize = 4;

/// A QR code, as the square of light/dark modules a window paints.
#[derive(Clone)]
pub struct QrArt {
    /// The symbol's side length in modules, excluding the quiet zone.
    size: usize,
    /// Row-major, one byte per module: 1 dark, 0 light. Zeroized on drop — these bytes ARE the secret.
    modules: Zeroizing<Vec<u8>>,
}

/// Written out rather than derived because [`Zeroizing`] has no [`PartialEq`], and because the
/// comparison a caller wants is over the PATTERN — two `QrArt`s carrying the same modules are the same
/// picture. Needed at all so [`super::ConfirmContent`], which a test compares whole, keeps its derive.
impl PartialEq for QrArt {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && *self.modules == *other.modules
    }
}

impl Eq for QrArt {}

impl std::fmt::Debug for QrArt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The pattern encodes the secret, so it is described rather than printed.
        write!(f, "QrArt({} modules square, <redacted>)", self.size)
    }
}

impl QrArt {
    /// Encode `text`, or `None` when it does not fit in any QR version.
    ///
    /// `None` rather than a panic or an empty square: a window that could not draw a QR must still
    /// draw its other, sufficient path to the same secret (the typed key), and a caller that cannot
    /// distinguish "no QR" from "a blank QR" would show the user an empty white box to point a camera
    /// at forever.
    pub fn encode(text: &str) -> Option<Self> {
        let code = qrcodegen::QrCode::encode_text(text, ERROR_CORRECTION).ok()?;
        let size = usize::try_from(code.size()).ok()?;
        let mut modules = Zeroizing::new(vec![0u8; size * size]);
        for y in 0..size {
            for x in 0..size {
                // `get_module` takes signed coordinates and returns false out of bounds; both loops are
                // bounded by the code's own size, so the casts are exact.
                modules[y * size + x] = u8::from(code.get_module(x as i32, y as i32));
            }
        }
        Some(Self { size, modules })
    }

    /// The symbol's side in modules, quiet zone EXCLUDED.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The side in modules a window must reserve: the symbol plus a quiet zone each side.
    pub fn total_modules(&self) -> usize {
        self.size + QUIET_MODULES * 2
    }

    /// Whether the module at `(x, y)` is dark. Out-of-range coordinates are LIGHT.
    ///
    /// Out-of-range answering "light" rather than panicking is what lets the painting loop walk the
    /// full reserved square — quiet zone included — with one expression instead of a bounds test that
    /// would have to agree with [`total_modules`](Self::total_modules) separately.
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        self.modules[y * self.size + x] == 1
    }

    /// The `(column, row)` of every DARK module, in coordinates of the RESERVED square — the quiet
    /// zone already added.
    ///
    /// Quiet-shifted here rather than at the call site so the painting code multiplies by a module
    /// size and adds an origin, and nothing outside this module has to know how wide a quiet zone is.
    /// A second place holding that number is a second place it can be wrong, and a QR drawn flush to
    /// the window chrome is one most decoders refuse.
    pub fn dark_modules(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        (0..self.size).flat_map(move |y| {
            (0..self.size)
                .filter(move |x| self.is_dark(*x, y))
                .map(move |x| (x + QUIET_MODULES, y + QUIET_MODULES))
        })
    }

    /// How many PIXELS wide each module should be drawn, to fill up to `available` pixels.
    ///
    /// # Why this floors to a whole number, and why that is the point
    ///
    /// A QR is read by sampling module centres. Draw modules at a fractional pixel size and their
    /// edges land on different pixel boundaries down the symbol, so the timing pattern — the run of
    /// alternating modules a decoder uses to find every other module's centre — comes out with uneven
    /// runs. That is a symbol that photographs cleanly and refuses to scan.
    ///
    /// So the module size is `floor(available / total)` and the drawn symbol is *at most* `available`
    /// wide, with the remainder left as extra margin. The floor is at least 1: a symbol one pixel per
    /// module is small, but a symbol ZERO pixels per module is invisible, and this returning 0 would
    /// silently draw nothing at all on a display too small for the design.
    ///
    /// Because `available` is itself derived from the DPI-scaled design units, a 250% display gets 2.5x
    /// the pixels and therefore ~2.5x the module size — the QR grows with the window instead of
    /// staying a fixed-pixel postage stamp (dig_ecosystem#1832).
    pub fn module_pixels(&self, available: i32) -> i32 {
        let total = self.total_modules() as i32;
        (available / total.max(1)).max(1)
    }

    /// The drawn side length in pixels at `module_px` — the quiet zone included, so this is exactly the
    /// square the window must clear to white.
    pub fn drawn_pixels(&self, module_px: i32) -> i32 {
        self.total_modules() as i32 * module_px
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic payload: the shape and length of a real `otpauth://` provisioning URI, so every size
    /// assertion below is made against the symbol this window will actually draw rather than a short
    /// string that lands in a much smaller QR version.
    const PROVISIONING_URI: &str = "otpauth://totp/DIG%20Network?secret=JBSWY3DPEHPK3PXPJBSWY3DP\
                                    EHPK3PXP&issuer=DIG%20Network&algorithm=SHA1&digits=6&period=30";

    /// Every QR version is `21 + 4(v-1)` modules square, for v in 1..=40. A size outside that set means
    /// the matrix was copied with an off-by-one, which would shift every module and produce a square
    /// that photographs like a QR and decodes as nothing.
    #[test]
    fn the_matrix_is_a_real_qr_version_size() {
        let art = QrArt::encode(PROVISIONING_URI).expect("a URI fits in a QR");
        assert!(
            (21..=177).contains(&art.size()) && (art.size() - 21) % 4 == 0,
            "{} is not a QR version size",
            art.size()
        );
    }

    /// The three finder patterns, and the ABSENCE of a fourth.
    ///
    /// This is the structural property a decoder actually looks for, and it is asserted at all four
    /// corners rather than one: a matrix read back mirrored, or with its rows reversed, still has
    /// finders — just in the wrong corners. Checking that the bottom-right is CLEAR is what makes the
    /// test able to fail; the three positive checks alone cannot distinguish an orientation.
    #[test]
    fn the_finder_patterns_sit_in_three_corners_and_not_the_fourth() {
        let art = QrArt::encode(PROVISIONING_URI).expect("a URI fits in a QR");
        let last = art.size() - 7;

        for (ox, oy, corner) in [
            (0, 0, "top-left"),
            (last, 0, "top-right"),
            (0, last, "bottom-left"),
        ] {
            assert!(is_a_finder(&art, ox, oy), "no {corner} finder pattern");
        }
        // The bottom-right corner carries data (and, from version 2 up, a 5x5 ALIGNMENT pattern that a
        // loose 'dark ring, dark centre' heuristic mistakes for a finder — which is why this compares
        // the whole 7x7). A finder here means the matrix came back mirrored or rotated.
        assert!(
            !is_a_finder(&art, last, last),
            "a finder in the fourth corner means the matrix was read back in the wrong orientation"
        );
    }

    /// Whether the 7x7 block whose top-left module is `(ox, oy)` is a finder pattern — the exact
    /// ISO/IEC 18004 shape, spelled out, because that is the thing a decoder searches for.
    ///
    /// Compared in FULL rather than by sampling a corner and a centre: the sampled version passes on
    /// the 5x5 alignment pattern every version-2-and-up symbol carries near the bottom-right, so it
    /// cannot tell a correctly-oriented matrix from a mirrored one.
    fn is_a_finder(art: &QrArt, ox: usize, oy: usize) -> bool {
        const FINDER: [&str; 7] = [
            "#######", "#     #", "# ### #", "# ### #", "# ### #", "#     #", "#######",
        ];
        FINDER.iter().enumerate().all(|(dy, row)| {
            row.bytes()
                .enumerate()
                .all(|(dx, cell)| art.is_dark(ox + dx, oy + dy) == (cell == b'#'))
        })
    }

    /// Two different strings produce different matrices — a stub returning a fixed pattern would pass
    /// every structural assertion above.
    #[test]
    fn different_text_produces_a_different_matrix() {
        let a = QrArt::encode(PROVISIONING_URI).expect("encodes");
        let b = QrArt::encode(&PROVISIONING_URI.replace("JBSW", "MZXW")).expect("encodes");
        assert_ne!(a, b);
    }

    /// The reserved square is the symbol plus four modules of quiet zone on EACH side — eight in total,
    /// not four. A decoder locates the finders by their contrast against that clear space, so half a
    /// quiet zone is a symbol many phones refuse.
    #[test]
    fn the_reserved_square_carries_a_quiet_zone_on_both_sides() {
        let art = QrArt::encode(PROVISIONING_URI).expect("encodes");
        assert_eq!(art.total_modules(), art.size() + 8);
    }

    /// The module size is a WHOLE number of pixels and the drawn symbol never exceeds its allotment.
    ///
    /// Both halves matter and they fail differently: a fractional size gives uneven timing runs that
    /// will not scan, and a symbol wider than its allotment overlaps whatever the layout put beside it.
    /// The widths span the DPI range this window really sees — 100% through 250% of the design's
    /// allotment — because a rule that only holds at one scale is the postage-stamp bug (#1832) again.
    #[test]
    fn modules_are_whole_pixels_and_the_symbol_fits_its_allotment() {
        let art = QrArt::encode(PROVISIONING_URI).expect("encodes");
        for available in [200, 260, 340, 420, 500, 650] {
            let px = art.module_pixels(available);
            assert!(
                px >= 1,
                "a module must be at least one pixel at {available}"
            );
            assert!(
                art.drawn_pixels(px) <= available,
                "the symbol must fit inside {available} px, drew {}",
                art.drawn_pixels(px)
            );
            // ...and it must genuinely FILL it: floor(available/total) can waste at most one module's
            // width, so anything smaller than that means the size was not maximised.
            assert!(
                art.drawn_pixels(px) + art.total_modules() as i32 > available,
                "the symbol wastes more than a module of {available} px"
            );
        }
    }

    /// The painted modules are the dark ones, SHIFTED by the quiet zone.
    ///
    /// Both halves are load-bearing and fail differently. Without the shift the symbol is painted flush
    /// against the window chrome, which is a QR most decoders will not read at all — and the shift is
    /// invisible in a screenshot, because a symbol drawn four modules too far up and left still LOOKS
    /// exactly like a QR code. Without the right COUNT, modules are missing or doubled.
    ///
    /// The top-left finder's corner module pins the offset: it is dark, it is at symbol `(0, 0)`, and it
    /// must therefore appear at reserved-square `(4, 4)` and nowhere else.
    #[test]
    fn painted_modules_are_the_dark_ones_offset_by_the_quiet_zone() {
        let art = QrArt::encode(PROVISIONING_URI).expect("encodes");
        let painted: Vec<_> = art.dark_modules().collect();

        let mut dark_count = 0;
        for y in 0..art.size() {
            for x in 0..art.size() {
                dark_count += usize::from(art.is_dark(x, y));
            }
        }
        assert_eq!(
            painted.len(),
            dark_count,
            "every dark module, and only those"
        );

        assert!(
            painted.contains(&(4, 4)),
            "the top-left finder's corner module must land one quiet zone in"
        );
        assert!(
            !painted.contains(&(0, 0)),
            "a module at the very corner means the quiet zone was not applied"
        );
        // Nothing may be painted outside the reserved square, or it lands on whatever the layout put
        // beside the QR.
        let limit = art.total_modules();
        assert!(painted.iter().all(|(x, y)| *x < limit && *y < limit));
    }

    /// A cramped allotment still draws something. Returning 0 here would paint an invisible QR while
    /// every other assertion in this file passed.
    #[test]
    fn a_tiny_allotment_still_draws_one_pixel_per_module() {
        let art = QrArt::encode(PROVISIONING_URI).expect("encodes");
        assert_eq!(art.module_pixels(1), 1);
        assert_eq!(art.module_pixels(0), 1);
    }

    /// Out-of-range coordinates read as light, so the painting loop can walk the quiet zone without a
    /// separate bounds test that could disagree with `total_modules`.
    #[test]
    fn coordinates_outside_the_symbol_are_light() {
        let art = QrArt::encode(PROVISIONING_URI).expect("encodes");
        assert!(!art.is_dark(art.size(), 0));
        assert!(!art.is_dark(0, art.size()));
        assert!(!art.is_dark(usize::MAX, usize::MAX));
    }

    /// `Debug` describes the square instead of printing it — the modules ARE the secret, so a derived
    /// `Debug` would be enough to put a scannable credential into a panic message.
    #[test]
    fn debug_never_prints_the_pattern() {
        let art = QrArt::encode(PROVISIONING_URI).expect("encodes");
        let rendered = format!("{art:?}");
        assert!(rendered.contains("redacted"), "{rendered}");
        // A printed matrix is thousands of characters; a description is a few dozen. Bounding the
        // LENGTH is what makes this fail on a derived `Debug`, which would happily contain the word
        // "redacted" nowhere and the whole pattern everywhere.
        assert!(
            rendered.len() < 64,
            "the pattern itself appears to be in the output: {rendered}"
        );
    }
}
