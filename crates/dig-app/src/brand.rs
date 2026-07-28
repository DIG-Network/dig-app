//! The DIG brand mark, embedded in the shell binary for its tray / menu-bar icon.
//!
//! The tray icon is the one piece of DIG a user sees for their whole session, so the mark travels
//! *inside* the binary: `include_bytes!` of a PNG checked in beside this module, decoded to RGBA at
//! startup. Nothing is read from disk and nothing is shared with another submodule at build or run
//! time, so a `dig-app` binary is self-contained however it was packaged.
//!
//! Decoding is **fallible and non-panicking** by design. A corrupt asset should cost the tray its
//! picture and nothing else — never the user's whole agent — so every entry point here returns a
//! [`Result`] and the shell falls back to an icon-less tray. See `brand_icon` in
//! `src/bin/dig-app.rs`.
//!
//! This module is part of the `tray` feature: a `--no-default-features` headless build carries
//! neither the embedded PNGs nor the PNG decoder.

use std::fmt;

/// The mark at the size Windows paints a notification-area icon at.
///
/// Windows asks for 16 logical px, which is 32 device px at the 200% scaling a modern laptop panel
/// uses — so this source is a 1:1 or 2:1 match and needs no resampling in the common cases.
pub const MARK_32: &[u8] = include_bytes!("../icons/mark-32.png");

/// The mark at the size a macOS menu bar and a Linux panel paint at.
///
/// A macOS menu bar is 22pt tall — 44 device px on a Retina display — and Linux panel indicators sit
/// in the 22-32px range. Both take this source and downscale slightly, which is far kinder to the
/// glyph than downscaling the 128px master: at these sizes the master's fine anti-aliasing collapses
/// into mush.
pub const MARK_64: &[u8] = include_bytes!("../icons/mark-64.png");

/// The embedded mark for the current platform's tray, chosen by that platform's paint size.
#[cfg(target_os = "windows")]
pub const TRAY_MARK: &[u8] = MARK_32;

/// The embedded mark for the current platform's tray, chosen by that platform's paint size.
#[cfg(not(target_os = "windows"))]
pub const TRAY_MARK: &[u8] = MARK_64;

/// A decoded 8-bit RGBA bitmap — the pixel buffer plus the dimensions needed to interpret it.
///
/// This is exactly the shape `tray_icon::Icon::from_rgba` consumes, so the shell can hand it
/// straight over without touching individual pixels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bitmap {
    /// Row-major RGBA8 pixels: `4 * width * height` bytes.
    pub rgba: Vec<u8>,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl Bitmap {
    /// The pixel at `(x, y)` as `[r, g, b, a]`, or `None` if the coordinate is outside the bitmap.
    ///
    /// Provided for the conformance tests that check the mark is the mark — the shell itself never
    /// inspects pixels.
    pub fn pixel(&self, x: u32, y: u32) -> Option<[u8; 4]> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let start = 4 * (y as usize * self.width as usize + x as usize);
        let px = self.rgba.get(start..start + 4)?;
        Some([px[0], px[1], px[2], px[3]])
    }
}

/// Why an embedded brand mark could not be turned into a [`Bitmap`].
///
/// Both variants carry the decoder's own description so the shell can log *why* the tray is bare
/// without this module needing to enumerate every failure the PNG format allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkError {
    /// The bytes are not a PNG this decoder can read: bad signature, truncated stream, or corrupt
    /// compressed data.
    Undecodable(String),
    /// A readable PNG, but not the 8-bit RGBA a tray icon needs.
    NotRgba8(String),
}

impl fmt::Display for MarkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undecodable(why) => write!(f, "brand mark is not a readable PNG: {why}"),
            Self::NotRgba8(what) => write!(f, "brand mark is not 8-bit RGBA: {what}"),
        }
    }
}

impl std::error::Error for MarkError {}

/// Decode an embedded brand-mark PNG into 8-bit RGBA.
///
/// The marks are authored as RGBA8, and that is asserted rather than converted: a mark that arrives
/// in some other colour type is a packaging mistake worth reporting, not something to silently
/// reinterpret into a wrong-looking icon.
pub fn decode(png_bytes: &[u8]) -> Result<Bitmap, MarkError> {
    let mut reader = png::Decoder::new(png_bytes)
        .read_info()
        .map_err(|e| MarkError::Undecodable(e.to_string()))?;

    // Copy the format out before `next_frame` takes the reader mutably.
    let (color_type, bit_depth) = {
        let info = reader.info();
        (info.color_type, info.bit_depth)
    };
    if color_type != png::ColorType::Rgba || bit_depth != png::BitDepth::Eight {
        return Err(MarkError::NotRgba8(format!("{color_type:?}/{bit_depth:?}")));
    }

    let mut rgba = vec![0u8; reader.output_buffer_size()];
    let frame = reader
        .next_frame(&mut rgba)
        .map_err(|e| MarkError::Undecodable(e.to_string()))?;
    rgba.truncate(frame.buffer_size());

    Ok(Bitmap {
        rgba,
        width: frame.width,
        height: frame.height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both embedded marks, with the square edge each one declares, so every conformance property
    /// below is checked against *both* assets on every platform — not just the one this host picks.
    fn marks() -> [(&'static str, &'static [u8], u32); 2] {
        [("mark-32", MARK_32, 32), ("mark-64", MARK_64, 64)]
    }

    /// A pixel counts as part of the mark's magenta ground when it is clearly more red+blue than
    /// green. The old placeholder was teal (`#129E76`), whose green dominates, so this predicate
    /// separates the real mark from that regression rather than merely from "some colour".
    fn is_magenta([r, g, b, _]: [u8; 4]) -> bool {
        i32::from(r) - i32::from(g) > 40 && b > 100
    }

    #[test]
    fn embedded_marks_decode_at_their_declared_size() {
        for (name, bytes, edge) in marks() {
            let mark = decode(bytes).unwrap_or_else(|e| panic!("{name} failed to decode: {e}"));
            assert_eq!(mark.width, edge, "{name} width");
            assert_eq!(mark.height, edge, "{name} height");
            assert_eq!(
                mark.rgba.len() as u32,
                4 * edge * edge,
                "{name} buffer must be 4 bytes per pixel"
            );
        }
    }

    /// The regression this whole module exists to prevent: the tray used to paint a single flat
    /// colour over every pixel. A solid fill has exactly ONE distinct RGBA value, so requiring many
    /// distinct values fails on that implementation and on any trivial gradient standing in for art.
    #[test]
    fn embedded_marks_are_not_a_flat_colour() {
        for (name, bytes, _) in marks() {
            let mark = decode(bytes).expect("decodes");
            let distinct: std::collections::HashSet<[u8; 4]> = mark
                .rgba
                .chunks_exact(4)
                .map(|p| [p[0], p[1], p[2], p[3]])
                .collect();
            assert!(
                distinct.len() > 100,
                "{name} has only {} distinct RGBA values — a flat or near-flat placeholder, not the \
                 brand mark",
                distinct.len()
            );
        }
    }

    /// The mark is a *disc*, so its four corners fall outside the artwork and must be fully
    /// transparent. A square block of colour — the failure mode that paints an ugly opaque tile on a
    /// light or dark tray alike — cannot satisfy this, which is what makes it load-bearing rather
    /// than a restatement of the non-flat test above.
    #[test]
    fn embedded_marks_have_transparent_corners_so_the_tray_shows_a_disc_not_a_tile() {
        for (name, bytes, edge) in marks() {
            let mark = decode(bytes).expect("decodes");
            let last = edge - 1;
            for (x, y) in [(0, 0), (last, 0), (0, last), (last, last)] {
                let px = mark.pixel(x, y).expect("corner is in bounds");
                assert_eq!(
                    px[3], 0,
                    "{name} corner ({x},{y}) has alpha {} — the mark must not be an opaque tile",
                    px[3]
                );
            }
        }
    }

    /// Real alpha across the full range, not a stripped or all-opaque channel. An icon that decoded
    /// but lost its alpha would paint a light rectangle behind the disc, which is precisely the
    /// dark-tray failure the disc silhouette avoids.
    #[test]
    fn embedded_marks_carry_a_non_trivial_alpha_channel() {
        for (name, bytes, _) in marks() {
            let mark = decode(bytes).expect("decodes");
            let alphas: Vec<u8> = mark.rgba.chunks_exact(4).map(|p| p[3]).collect();
            let min = *alphas.iter().min().expect("non-empty");
            let max = *alphas.iter().max().expect("non-empty");
            assert_eq!(min, 0, "{name} must contain fully transparent pixels");
            assert_eq!(max, 255, "{name} must contain fully opaque pixels");

            let partial = alphas.iter().filter(|&&a| a > 0 && a < 255).count();
            assert!(
                partial > alphas.len() / 20,
                "{name} has only {partial} anti-aliased pixels — the disc edge would look jagged at \
                 tray size"
            );
        }
    }

    /// The mark's ground is DIG magenta and its centre is filled. Together these pin the asset's
    /// identity: the teal placeholder fails the hue check, and a hollow ring or an empty canvas
    /// fails the opaque-centre check.
    #[test]
    fn embedded_marks_are_the_magenta_dig_disc() {
        for (name, bytes, edge) in marks() {
            let mark = decode(bytes).expect("decodes");

            let centre = mark.pixel(edge / 2, edge / 2).expect("centre is in bounds");
            assert!(
                centre[3] > 128,
                "{name} centre is transparent (alpha {}) — the disc must be filled",
                centre[3]
            );

            let opaque: Vec<[u8; 4]> = mark
                .rgba
                .chunks_exact(4)
                .map(|p| [p[0], p[1], p[2], p[3]])
                .filter(|p| p[3] > 200)
                .collect();
            let magenta = opaque.iter().copied().filter(|&p| is_magenta(p)).count();
            assert!(
                magenta * 4 > opaque.len(),
                "{name}: only {magenta} of {} solid pixels are DIG magenta — this is not the brand \
                 mark",
                opaque.len()
            );
        }
    }

    /// The whole point of returning a `Result`: a bad asset must not panic the shell. Two distinct
    /// failure paths are exercised — a stream that never looks like a PNG, and one whose header
    /// parses but whose pixel data is cut off — because a decoder can fail at either stage.
    #[test]
    fn a_corrupt_mark_is_an_error_and_never_a_panic() {
        let garbage = decode(b"this is definitely not a PNG");
        assert!(
            matches!(garbage, Err(MarkError::Undecodable(_))),
            "non-PNG bytes must report Undecodable, got {garbage:?}"
        );

        // A real PNG header followed by a truncated body: the signature and IHDR parse, so this
        // reaches the pixel-decoding stage that the garbage case never gets to.
        let truncated = decode(&MARK_32[..MARK_32.len() / 2]);
        assert!(
            truncated.is_err(),
            "a truncated mark must be an error, got a bitmap"
        );
    }

    /// The platform mark is one of the two embedded assets and decodes on this host, so the shell's
    /// startup path cannot be silently pointing at nothing.
    #[test]
    fn the_platform_tray_mark_is_an_embedded_asset_that_decodes() {
        assert!(
            TRAY_MARK == MARK_32 || TRAY_MARK == MARK_64,
            "TRAY_MARK must be one of the embedded marks"
        );
        assert!(decode(TRAY_MARK).is_ok(), "the platform mark must decode");
    }

    #[test]
    fn pixel_rejects_out_of_bounds_coordinates() {
        let mark = decode(MARK_32).expect("decodes");
        assert!(mark.pixel(32, 0).is_none());
        assert!(mark.pixel(0, 32).is_none());
        assert!(mark.pixel(31, 31).is_some());
    }

    #[test]
    fn mark_errors_describe_themselves_for_the_log() {
        let rendered = MarkError::Undecodable("bad signature".into()).to_string();
        assert!(rendered.contains("bad signature"), "got {rendered}");
        let rendered = MarkError::NotRgba8("Grayscale/Eight".into()).to_string();
        assert!(rendered.contains("Grayscale/Eight"), "got {rendered}");
    }
}
