//! What intake must be true of, and the fixtures that can actually tell.
//!
//! Two of these deserve a note before the code, because a weaker fixture would pass them while the
//! property was broken:
//!
//! * **"the base64 is the RESIZED image"** cannot be asserted by looking at the returned dimensions
//!   — a bug that resized correctly and then encoded the ORIGINAL bytes would report 500x250 and be
//!   wrong. So every such test **decodes the returned base64 back** and measures that.
//! * **the bomb** is a header declaring an enormous image with no pixel data behind it. If the
//!   refusal happened after decoding, that fixture would fail as truncated rather than as too large
//!   — so the assertion is on the error *carrying the declared dimensions*, which only a header-time
//!   refusal can know. It is deliberately NOT the fixture for the allocation claim — a header-only
//!   file allocates nothing even when the bound is removed, so it cannot tell a bounded decode from
//!   an unbounded one. That claim is bounded by a real bomb in
//!   `tests/profile_image_bomb_allocates_nothing.rs`, a separate binary because it needs its own
//!   global allocator.

use super::*;

/// A JPEG-encodable opaque image with per-pixel variation, so a resize cannot be faked by a
/// constant-colour shortcut and the encoder has real work to do.
fn opaque_png(width: u32, height: u32) -> Vec<u8> {
    let image = image::RgbImage::from_fn(width, height, |x, y| {
        image::Rgb([(x % 251) as u8, (y % 241) as u8, ((x ^ y) % 233) as u8])
    });
    encode_png(&DynamicImage::ImageRgb8(image))
}

/// The same, but with one genuinely translucent pixel — the single fact that must select PNG.
fn translucent_png(width: u32, height: u32) -> Vec<u8> {
    let mut image = image::RgbaImage::from_fn(width, height, |x, y| {
        image::Rgba([(x % 251) as u8, (y % 241) as u8, ((x ^ y) % 233) as u8, 255])
    });
    image.put_pixel(0, 0, image::Rgba([1, 2, 3, 128]));
    encode_png(&DynamicImage::ImageRgba8(image))
}

/// An RGBA image where every pixel is fully opaque — the control that separates "has an alpha
/// channel" from "needs one". A codec choice made on the source's colour type gets this wrong.
fn fully_opaque_rgba_png(width: u32, height: u32) -> Vec<u8> {
    let image = image::RgbaImage::from_fn(width, height, |x, y| {
        image::Rgba([(x % 251) as u8, (y % 241) as u8, ((x ^ y) % 233) as u8, 255])
    });
    encode_png(&DynamicImage::ImageRgba8(image))
}

fn encode_png(image: &DynamicImage) -> Vec<u8> {
    let mut bytes = Vec::new();
    image
        .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
        .expect("fixture encodes");
    bytes
}

/// Decode what intake actually stored. Every dimension assertion goes through this rather than
/// through the reported `width`/`height`, so an implementation that resized and then encoded the
/// original cannot pass.
fn stored_dimensions(url: &DataUrl) -> (u32, u32) {
    let bytes = STANDARD
        .decode(&url.base64)
        .expect("stored payload is base64");
    let image = image::load_from_memory(&bytes).expect("stored payload decodes");
    (image.width(), image.height())
}

#[test]
fn a_landscape_image_fits_the_box_by_its_own_proportions() {
    let url = intake(&opaque_png(1000, 500), DecodeBounds::LOCAL_PICK).expect("accepted");

    assert_eq!(stored_dimensions(&url), (500, 250));
    assert_eq!((url.width, url.height), (500, 250));
}

#[test]
fn a_portrait_image_fits_the_box_by_its_own_proportions() {
    let url = intake(&opaque_png(500, 1000), DecodeBounds::LOCAL_PICK).expect("accepted");

    assert_eq!(stored_dimensions(&url), (250, 500));
}

#[test]
fn an_awkward_ratio_keeps_its_aspect_and_touches_the_box_on_its_long_side() {
    // 903x301 is deliberately not a clean divisor of 500: a fit-within that rounds carelessly, or
    // that stretches to fill, shows up here and nowhere in the 2:1 cases above.
    let (width, height) = stored_dimensions(
        &intake(&opaque_png(903, 301), DecodeBounds::LOCAL_PICK).expect("accepted"),
    );

    assert_eq!(width, 500, "the long side lands exactly on the box");
    assert!(height <= FIT_BOX);
    let source_ratio = 903.0 / 301.0;
    let stored_ratio = f64::from(width) / f64::from(height);
    assert!(
        (source_ratio - stored_ratio).abs() < 0.02,
        "aspect ratio {stored_ratio} drifted from {source_ratio}"
    );
}

#[test]
fn an_image_already_inside_the_box_is_not_upscaled() {
    let url = intake(&opaque_png(200, 150), DecodeBounds::LOCAL_PICK).expect("accepted");

    assert_eq!(stored_dimensions(&url), (200, 150));
}

#[test]
fn the_box_is_pinned_from_both_sides() {
    // At the bound: untouched, so no resample is spent on an image that already conforms.
    assert_eq!(
        stored_dimensions(&intake(&opaque_png(500, 500), DecodeBounds::LOCAL_PICK).expect("ok")),
        (500, 500)
    );
    // One pixel over: resized, and the long side comes back to exactly the box.
    let (width, height) =
        stored_dimensions(&intake(&opaque_png(501, 500), DecodeBounds::LOCAL_PICK).expect("ok"));
    assert_eq!(width, 500);
    assert!(height < 500, "the short side shrinks with it, got {height}");
}

#[test]
fn the_stored_payload_is_the_resized_encoding_not_the_original_bytes() {
    let original = opaque_png(1000, 500);
    let url = intake(&original, DecodeBounds::LOCAL_PICK).expect("accepted");

    let stored = STANDARD.decode(&url.base64).expect("base64");
    assert_ne!(stored, original, "the original bytes were stored verbatim");
    assert!(
        stored.len() < original.len(),
        "a resized encoding of {} bytes is not smaller than the {} byte original",
        stored.len(),
        original.len()
    );
    assert_eq!(stored_dimensions(&url), (500, 250));
}

#[test]
fn transparency_selects_png_and_its_absence_selects_jpeg() {
    let transparent = intake(&translucent_png(600, 600), DecodeBounds::LOCAL_PICK).expect("ok");
    assert_eq!(transparent.mime, "image/png");

    let opaque = intake(&opaque_png(600, 600), DecodeBounds::LOCAL_PICK).expect("ok");
    assert_eq!(opaque.mime, "image/jpeg");
}

#[test]
fn an_alpha_channel_that_is_entirely_opaque_still_selects_jpeg() {
    // The distinguishing case for the codec rule: an implementation that branched on the source's
    // colour type would emit a PNG here, several times the size, for an image needing no alpha.
    let url = intake(&fully_opaque_rgba_png(600, 600), DecodeBounds::LOCAL_PICK).expect("ok");

    assert_eq!(url.mime, "image/jpeg");
}

#[test]
fn the_worst_case_output_stays_inside_the_slot_budget() {
    // Random-ish noise with alpha is the least compressible thing the PNG branch can be handed, so
    // this is the closest an actual encode gets to the bound the slot budget is derived from.
    let url = intake(&translucent_png(900, 900), DecodeBounds::LOCAL_PICK).expect("ok");

    assert_eq!(url.mime, "image/png");
    assert!(
        url.base64.len() <= WORST_CASE_ENCODED_BYTES * 4 / 3 + 4,
        "base64 payload of {} bytes exceeds the derived budget",
        url.base64.len()
    );
    assert!(url.url_len() > url.base64.len());
    assert!(url.to_url().starts_with("data:image/png;base64,"));
}

#[test]
fn an_svg_is_refused_as_an_unsupported_format() {
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;

    assert_eq!(
        intake(svg, DecodeBounds::LOCAL_PICK),
        Err(IntakeError::UnsupportedFormat)
    );
    assert!(!is_accepted_mime("image/svg+xml"));
    assert!(is_accepted_mime("image/png"));
    assert!(is_accepted_mime("IMAGE/JPEG"));
}

#[test]
fn a_valid_image_of_an_uncompiled_format_is_refused_rather_than_decoded() {
    // A real GIF header. The point is that this is a *legitimate* image — it is refused because
    // this build has no GIF decoder linked, which is the attack surface the feature list removes.
    let gif = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!";

    assert_eq!(
        intake(gif, DecodeBounds::LOCAL_PICK),
        Err(IntakeError::UnsupportedFormat)
    );
}

#[test]
fn a_truncated_png_is_reported_as_damaged_not_as_unsupported() {
    let mut bytes = opaque_png(64, 64);
    bytes.truncate(bytes.len() / 2);

    assert_eq!(
        intake(&bytes, DecodeBounds::LOCAL_PICK),
        Err(IntakeError::Corrupt)
    );
}

#[test]
fn a_decompression_bomb_is_refused_with_the_dimensions_it_declared() {
    let bomb = bomb_header(60_000, 60_000);

    let refusal = intake(&bomb, DecodeBounds::LOCAL_PICK).expect_err("a bomb is never accepted");

    assert_eq!(
        refusal,
        IntakeError::TooLarge {
            width: 60_000,
            height: 60_000,
            limit: 8192,
        },
        "the refusal must name what the header declared, which only a header-time refusal knows"
    );
    let message = refusal.to_string();
    assert!(
        message.contains("60000") && message.contains("8192"),
        "{message}"
    );
}

#[test]
fn the_received_bound_refuses_what_the_local_bound_accepts() {
    // One fixture, two profiles: this is what proves the two limit sets are genuinely distinct
    // rather than one bound wearing two names.
    let image = opaque_png(600, 600);

    assert!(intake(&image, DecodeBounds::LOCAL_PICK).is_ok());
    assert_eq!(
        intake(&image, DecodeBounds::RECEIVED),
        Err(IntakeError::TooLarge {
            width: 600,
            height: 600,
            limit: 512,
        })
    );
    // And a conforming body — one our own writer could have produced — still passes the tight one.
    assert!(intake(&opaque_png(500, 500), DecodeBounds::RECEIVED).is_ok());
}

#[test]
fn the_total_pixel_count_is_capped_independently_of_each_side() {
    // Both sides are inside 8192, so a per-side check alone would let 60 megapixels through.
    let bounds = DecodeBounds {
        max_pixels: 1_000_000,
        ..DecodeBounds::LOCAL_PICK
    };

    assert_eq!(
        intake(&bomb_header(8000, 8000), bounds),
        Err(IntakeError::TooLarge {
            width: 8000,
            height: 8000,
            limit: 8192,
        })
    );
}

#[test]
fn an_over_long_input_is_refused_before_anything_is_parsed() {
    let bounds = DecodeBounds {
        max_input_bytes: 16,
        ..DecodeBounds::RECEIVED
    };
    let image = opaque_png(8, 8);

    assert_eq!(
        intake(&image, bounds),
        Err(IntakeError::InputTooLong {
            len: image.len(),
            limit: 16,
        })
    );
}

#[test]
fn every_refusal_reads_as_a_sentence_a_person_can_act_on() {
    for refusal in [
        IntakeError::UnsupportedFormat,
        IntakeError::TooLarge {
            width: 9,
            height: 9,
            limit: 8,
        },
        IntakeError::InputTooLong { len: 9, limit: 8 },
        IntakeError::Corrupt,
        IntakeError::EncodeFailed,
    ] {
        let message = refusal.to_string();
        assert!(message.ends_with('.'), "{message}");
        assert!(
            !message.to_ascii_lowercase().contains("error")
                && !message.contains("Limits")
                && !message.contains("::"),
            "a decoder's own words leaked into: {message}"
        );
    }
}

/// A PNG that declares `width x height` and carries no pixel data at all — a decompression bomb in
/// its purest form, a few dozen bytes standing in for a multi-gigabyte bitmap.
///
/// Built by patching a real one-pixel PNG's IHDR rather than by encoding a huge image, for the
/// obvious reason that encoding one would allocate exactly what this test exists to prove is never
/// allocated. The CRC is recomputed because a PNG decoder checks it before trusting the header, and
/// a fixture that failed on a bad CRC would be refused for the wrong reason.
pub(crate) fn bomb_header(width: u32, height: u32) -> Vec<u8> {
    let mut bytes = opaque_png(1, 1);
    bytes[16..20].copy_from_slice(&width.to_be_bytes());
    bytes[20..24].copy_from_slice(&height.to_be_bytes());
    let crc = crc32(&bytes[12..29]);
    bytes[29..33].copy_from_slice(&crc.to_be_bytes());
    bytes
}

/// The CRC-32 PNG chunks are checked against (IEEE polynomial, reflected).
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[test]
fn the_bomb_fixture_is_a_well_formed_png_header_and_not_merely_garbage() {
    // Without this the bomb test could be passing on a corrupt-CRC rejection dressed up as a size
    // refusal — the fixture has to be a header a decoder genuinely believes.
    let bomb = bomb_header(60_000, 60_000);

    assert_eq!(image::guess_format(&bomb).ok(), Some(ImageFormat::Png));
    let dimensions = reader_for(&bomb, ImageFormat::Png, Limits::no_limits())
        .into_dimensions()
        .expect("the header parses cleanly");
    assert_eq!(dimensions, (60_000, 60_000));
}

// ---------------------------------------------------------------------------------------------
// The preview a form draws (dig_ecosystem#3028)
// ---------------------------------------------------------------------------------------------

/// **A preview shows the image that will actually be STORED, at the size it will be stored.**
///
/// Measured against the round trip rather than against the source, because that is the property a
/// person is reading off the screen: they picked a 1200x600 photograph and what goes on chain is the
/// 500x250 normalisation, so a preview of the ORIGINAL would show them something the network never
/// sees.
#[test]
fn a_preview_is_of_the_normalised_image_the_slot_will_hold() {
    let stored = intake(&opaque_png(1200, 600), DecodeBounds::LOCAL_PICK).expect("a real picture");
    let shown = preview(&stored.to_url()).expect("the stored value previews");

    assert_eq!((shown.width, shown.height), (500, 250));
    assert_eq!(
        (shown.width, shown.height),
        stored_dimensions(&stored),
        "the preview and the stored bytes are different images"
    );
    assert_eq!(shown.rgba.len(), 500 * 250 * 4);
}

/// **A bomb somebody PASTED into the field is refused by the preview, not decoded on the painting
/// thread.**
///
/// The fixture is a header declaring 60,000x60,000 with no pixels behind it — the same one the
/// intake bomb tests use — wrapped as a well-formed `data:image/png;base64,` value. That matters
/// twice over: the value is one the field genuinely accepts as *shaped* like an image, so the
/// preview is the only thing standing between the paste and the decoder, and a preview written with
/// no bounds at all would answer this with a 60,000-pixel-wide allocation rather than with `None`.
///
/// The control below is what stops this passing on a preview that refuses everything.
#[test]
fn a_pasted_bomb_is_refused_by_the_preview() {
    let bomb = format!(
        "data:image/png;base64,{}",
        STANDARD.encode(bomb_header(60_000, 60_000))
    );
    assert_eq!(
        preview(&bomb),
        None,
        "a declared 60,000px image was decoded"
    );

    let honest = intake(&opaque_png(64, 64), DecodeBounds::LOCAL_PICK).expect("a real picture");
    assert!(
        preview(&honest.to_url()).is_some(),
        "the preview refuses an ordinary picture too, so the refusal above proves nothing"
    );
}

/// Anything that is not a `data:` URL of an accepted type previews as nothing — including the SVG
/// this module refuses by name everywhere else.
#[test]
fn only_an_accepted_data_url_previews() {
    for value in [
        "",
        "me.png",
        "https://example.com/me.png",
        "data:image/svg+xml;base64,PHN2Zy8+",
        "data:image/png;base64,not-base64!!",
        "data:image/png;base64,",
    ] {
        assert_eq!(preview(value), None, "{value} previewed as an image");
    }
}
