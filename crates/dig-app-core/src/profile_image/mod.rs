//! Profile-image intake: turn a file a person chose (or a body a peer sent) into a bounded,
//! normalised data URL (dig_ecosystem#3010).
//!
//! # The one idea this module exists to hold
//!
//! **The size bound is on the OUTPUT; the attack is on the INPUT.** Resizing an image requires
//! decoding it first, and a decompression bomb is a few-kilobyte file whose header declares
//! dimensions that allocate gigabytes — all of it before a single pixel is resized. Clamping the
//! result to 500x500 does nothing about that, because the allocation has already happened.
//!
//! So intake is two bounds, not one:
//!
//! * a [`DecodeBounds`] applied to the header, **before** any pixel buffer is allocated, and
//! * the fit-within-500x500 normalisation applied to the decoded image.
//!
//! # Why this module is outside the `gui` feature
//!
//! Everything here is pure: bytes in, bytes out, no window, no picker, no event loop. That is what
//! makes the bomb refusal testable headlessly — and a bound that cannot be tested is a bound nobody
//! can trust. The file-picking and drag-and-drop surfaces call [`intake`]; they own no part of it.
//!
//! # What a caller gets
//!
//! [`intake`] returns a [`DataUrl`] whose payload is the **resized** encoding. The original is never
//! kept: the normalisation is lossy and one-way by design, because the stored bytes are what every
//! node has to sync.

use std::fmt;
use std::io::Cursor;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::{DynamicImage, ImageEncoder, ImageFormat, ImageReader, Limits};

/// The box every profile image is made to fit inside, in pixels, on both axes.
///
/// This is a **fit-within**, never a fill: a 1000x500 image becomes 500x250. Neither dimension may
/// exceed this and the aspect ratio is unchanged, so an image is bounded by its own proportions
/// rather than cropped.
pub const FIT_BOX: u32 = 500;

/// The JPEG quality used for images without transparency.
///
/// Pinned rather than tunable because the slot-size budget is derived from it — see
/// [`WORST_CASE_ENCODED_BYTES`].
const JPEG_QUALITY: u8 = 85;

/// The largest encoding [`intake`] can produce, in bytes, before base64.
///
/// A 500x500 RGBA PNG of incompressible noise is the worst case this module can emit:
/// `500 * 500 * 4` pixel bytes plus PNG framing ≈ 1,000,200 bytes, which base64 expands to
/// ≈ 1,333,600. That number is what makes a profile body cheap enough to gossip, and it is a
/// consequence of the pinned codec choice (PNG only when alpha is present, JPEG quality 85
/// otherwise). **Changing the codec choice invalidates this bound** and the slot budget derived
/// from it.
pub const WORST_CASE_ENCODED_BYTES: usize = FIT_BOX as usize * FIT_BOX as usize * 4 + 1_024;

/// How far a decoder may go before it is refused, applied to the header rather than to the result.
///
/// # Why a width/height pair and not just a byte cap
///
/// `image::Limits::max_alloc` is documented as **non-strict** — a decoder is permitted to exceed it
/// — so it cannot be the only thing standing between a hostile header and the allocator. The
/// `max_image_width` / `max_image_height` pair is strict, and the total-pixel cap here is enforced
/// by this module directly from the parsed header, before the decoder is asked for pixels at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeBounds {
    /// The greatest declared width, in pixels, that will be decoded.
    pub max_width: u32,
    /// The greatest declared height, in pixels, that will be decoded.
    pub max_height: u32,
    /// The greatest total pixel count, which is not implied by the two side limits: a
    /// `max_width x max_height` image is far larger than either side suggests on its own.
    pub max_pixels: u64,
    /// The greatest compressed input length accepted, refused before the header is even parsed.
    pub max_input_bytes: usize,
}

impl DecodeBounds {
    /// The bounds for a file the person at the keyboard picked or dragged in.
    ///
    /// Generous, because this input is the user's own photograph and refusing a normal camera image
    /// would be a defect, not a defence. 8192x8192 comfortably exceeds any consumer camera while
    /// still being three orders of magnitude below the dimensions a bomb declares.
    pub const LOCAL_PICK: Self = Self {
        max_width: 8192,
        max_height: 8192,
        max_pixels: 8192 * 8192,
        max_input_bytes: 256 * 1024 * 1024,
    };

    /// The bounds for an image arriving inside a body some other peer produced.
    ///
    /// Far tighter, and it is the normalisation rule that buys it: our own writer never emits more
    /// than [`FIT_BOX`] on a side, so anything larger arriving from the network was not produced by
    /// a conforming writer and has nothing to prove. Verified content is not safe content — a body
    /// that hashes correctly to the on-chain root can still carry a hostile image — so this path
    /// gets a hard bound rather than the benefit of the doubt.
    pub const RECEIVED: Self = Self {
        max_width: 512,
        max_height: 512,
        max_pixels: 512 * 512,
        max_input_bytes: 4 * 1024 * 1024,
    };

    /// The limits handed to the decoder itself, mirroring the strict half of this bound.
    fn decoder_limits(&self) -> Limits {
        let mut limits = Limits::no_limits();
        limits.max_image_width = Some(self.max_width);
        limits.max_image_height = Some(self.max_height);
        limits.max_alloc = Some(self.max_pixels.saturating_mul(4).saturating_add(1 << 20));
        limits
    }
}

/// A `data:` URL carrying the normalised image, ready to be stored or rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataUrl {
    /// The MIME type of the encoding actually produced — `image/png` or `image/jpeg`.
    pub mime: &'static str,
    /// The base64 of the **resized** encoding. Never the original bytes.
    pub base64: String,
    /// The width of the stored image, in pixels.
    pub width: u32,
    /// The height of the stored image, in pixels.
    pub height: u32,
}

impl DataUrl {
    /// The full `data:<mime>;base64,<payload>` form a renderer or an `<img>` consumes.
    pub fn to_url(&self) -> String {
        format!("data:{};base64,{}", self.mime, self.base64)
    }

    /// The length of [`to_url`](Self::to_url) without building it, for a caller checking a budget.
    pub fn url_len(&self) -> usize {
        "data:".len() + self.mime.len() + ";base64,".len() + self.base64.len()
    }
}

/// Why an image was refused, in terms a person can act on.
///
/// Each variant carries what the message has to say. A raw decoder error tells someone nothing they
/// can do something about, so none is ever surfaced verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntakeError {
    /// The bytes are not one of the accepted formats — including the case where they are a
    /// perfectly valid image of a format this build deliberately cannot decode.
    ///
    /// `image/svg+xml` lands here by design: an SVG is a script-bearing document, not a bitmap, and
    /// it is refused by name rather than by failing to parse.
    UnsupportedFormat,
    /// The header declares more image than the bound for this path allows. Carries the declared
    /// dimensions and the limit, because "too big" without either number is not actionable.
    TooLarge {
        /// The width the file declared.
        width: u64,
        /// The height the file declared.
        height: u64,
        /// The per-side limit that was exceeded, or the side limit nearest the pixel cap.
        limit: u32,
    },
    /// The input is longer than the path accepts, refused before the header is parsed.
    InputTooLong {
        /// The length offered.
        len: usize,
        /// The limit for this path.
        limit: usize,
    },
    /// The bytes claim a supported format but do not decode as one — truncated or corrupt.
    Corrupt,
    /// The resized image could not be re-encoded. Not a property of the input; a bug or an OOM.
    EncodeFailed,
}

impl fmt::Display for IntakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat => write!(
                f,
                "That file is not a supported image. Choose a PNG or a JPEG."
            ),
            Self::TooLarge {
                width,
                height,
                limit,
            } => write!(
                f,
                "That image is {width}x{height} pixels, larger than the {limit}x{limit} this app \
                 will open. Choose a smaller image."
            ),
            Self::InputTooLong { len, limit } => write!(
                f,
                "That file is {len} bytes, larger than the {limit} this app will open. Choose a \
                 smaller image."
            ),
            Self::Corrupt => write!(
                f,
                "That image could not be read — the file looks incomplete or damaged."
            ),
            Self::EncodeFailed => write!(f, "That image could not be prepared. Try another file."),
        }
    }
}

impl std::error::Error for IntakeError {}

/// The MIME types this module will accept a caller's *advisory* label of.
///
/// The label is never trusted on the received path — the real format is sniffed from the bytes —
/// but a caller that already knows the label can be refused earlier and told something clearer.
/// `image/svg+xml` is absent deliberately and is the reason this list exists at all.
pub const ACCEPTED_MIME_TYPES: [&str; 2] = ["image/png", "image/jpeg"];

/// Whether an advisory MIME label is one intake could possibly accept.
///
/// This is a courtesy check for a picker filter or a drop handler, **not** a security boundary: the
/// label on a dropped file is attacker-chosen on the received path, so [`intake`] sniffs the bytes
/// regardless of what any label said.
pub fn is_accepted_mime(mime: &str) -> bool {
    ACCEPTED_MIME_TYPES.contains(&mime.trim().to_ascii_lowercase().as_str())
}

/// Take raw image bytes and produce the normalised, base64-encoded data URL to store.
///
/// The pipeline, in the order that makes the bound meaningful:
///
/// 1. refuse an over-long input before parsing anything;
/// 2. sniff the real format from the bytes and refuse anything but PNG or JPEG;
/// 3. read the **header only** and refuse dimensions or a pixel count beyond `bounds` — this is the
///    step a decompression bomb dies at, and it happens before any pixel buffer exists;
/// 4. decode, with the decoder's own strict limits mirroring `bounds`;
/// 5. resize to fit within [`FIT_BOX`] on both sides, aspect ratio unchanged;
/// 6. re-encode: PNG if any resized pixel is even slightly transparent, JPEG quality 85 otherwise;
/// 7. base64 the **resized** encoding.
///
/// # An image smaller than the box is left alone
///
/// Upscaling adds bytes and no information, and it makes a small avatar look worse — so a 200x150
/// image comes back 200x150. This is an assumption, recorded on dig_ecosystem#3010 and overridable:
/// if every image should be normalised to exactly fill the box, this is the one place it changes.
///
/// # Which bounds to pass
///
/// [`DecodeBounds::LOCAL_PICK`] for a file the user chose; [`DecodeBounds::RECEIVED`] for anything
/// that came off the network. Never one for both — the whole value of the tight received bound is
/// that it is tight.
pub fn intake(bytes: &[u8], bounds: DecodeBounds) -> Result<DataUrl, IntakeError> {
    if bytes.len() > bounds.max_input_bytes {
        return Err(IntakeError::InputTooLong {
            len: bytes.len(),
            limit: bounds.max_input_bytes,
        });
    }

    let format = sniff_format(bytes)?;
    let decoded = decode_within(bytes, format, bounds)?;
    let resized = fit_within(decoded, FIT_BOX);
    encode(&resized)
}

/// Identify the format from the bytes themselves, refusing anything outside PNG and JPEG.
///
/// The caller's declared MIME is advisory on every path and attacker-chosen on the received one, so
/// it plays no part here.
fn sniff_format(bytes: &[u8]) -> Result<ImageFormat, IntakeError> {
    match image::guess_format(bytes) {
        Ok(format @ (ImageFormat::Png | ImageFormat::Jpeg)) => Ok(format),
        _ => Err(IntakeError::UnsupportedFormat),
    }
}

/// Read the header, refuse it against `bounds`, and only then decode.
///
/// Splitting the dimension check out of the decode is the entire defence. `into_dimensions` parses
/// the header and returns, allocating nothing proportional to the declared size, which is what lets
/// a bomb be refused with its real numbers in the error rather than with an allocation failure.
fn decode_within(
    bytes: &[u8],
    format: ImageFormat,
    bounds: DecodeBounds,
) -> Result<DynamicImage, IntakeError> {
    // Deliberately UNLIMITED for the header read alone. Parsing a header allocates nothing
    // proportional to the declared size, and a decoder that refused here would report only "limit
    // exceeded" — costing the actual dimensions, which are the one thing that makes the refusal
    // message actionable. The strict limits are still applied to the decode below.
    let (width, height) = reader_for(bytes, format, Limits::no_limits())
        .into_dimensions()
        .map_err(|err| classify(err, bounds))?;

    let pixels = u64::from(width) * u64::from(height);
    if width > bounds.max_width || height > bounds.max_height || pixels > bounds.max_pixels {
        return Err(IntakeError::TooLarge {
            width: u64::from(width),
            height: u64::from(height),
            limit: bounds.max_width.min(bounds.max_height),
        });
    }

    reader_for(bytes, format, bounds.decoder_limits())
        .decode()
        .map_err(|err| classify(err, bounds))
}

/// A reader pinned to the sniffed format and carrying the decoder-side half of the bound.
///
/// The format is set explicitly rather than re-guessed so the decoder cannot be talked into a
/// different parser than the one this module approved.
fn reader_for(bytes: &[u8], format: ImageFormat, limits: Limits) -> ImageReader<Cursor<&[u8]>> {
    let mut reader = ImageReader::new(Cursor::new(bytes));
    reader.set_format(format);
    reader.limits(limits);
    reader
}

/// Turn a decoder error into something a person can act on.
///
/// A limit trip is reported as [`IntakeError::TooLarge`] with the bound, because the decoder refuses
/// without telling us what it saw; everything else is a broken file.
fn classify(err: image::ImageError, bounds: DecodeBounds) -> IntakeError {
    match err {
        image::ImageError::Limits(_) => IntakeError::TooLarge {
            width: 0,
            height: 0,
            limit: bounds.max_width.min(bounds.max_height),
        },
        image::ImageError::Unsupported(_) => IntakeError::UnsupportedFormat,
        _ => IntakeError::Corrupt,
    }
}

/// Scale an image down so neither side exceeds `box_side`, leaving the aspect ratio alone.
///
/// An image already inside the box is returned untouched — see [`intake`] for why not upscaled.
fn fit_within(image: DynamicImage, box_side: u32) -> DynamicImage {
    if image.width() <= box_side && image.height() <= box_side {
        return image;
    }
    // `resize` is a fit-within by definition: it preserves the aspect ratio and guarantees both
    // sides land inside the requested box. Lanczos3 because a downscale by a large factor with a
    // cheaper filter aliases visibly on exactly the fine detail a face has.
    image.resize(box_side, box_side, image::imageops::FilterType::Lanczos3)
}

/// Encode the resized image, choosing the codec from whether it actually needs transparency.
///
/// PNG is used only when some pixel is not fully opaque, because PNG of a photograph is several
/// times the size of the JPEG and the stored bytes are what every node syncs. The pairing of these
/// two codecs is what [`WORST_CASE_ENCODED_BYTES`] is derived from.
fn encode(image: &DynamicImage) -> Result<DataUrl, IntakeError> {
    let (width, height) = (image.width(), image.height());
    let mut buffer = Vec::new();

    let mime = if has_transparency(image) {
        let rgba = image.to_rgba8();
        PngEncoder::new(&mut buffer)
            .write_image(
                rgba.as_raw(),
                width,
                height,
                image::ExtendedColorType::Rgba8,
            )
            .map_err(|_| IntakeError::EncodeFailed)?;
        "image/png"
    } else {
        let rgb = image.to_rgb8();
        JpegEncoder::new_with_quality(&mut buffer, JPEG_QUALITY)
            .write_image(rgb.as_raw(), width, height, image::ExtendedColorType::Rgb8)
            .map_err(|_| IntakeError::EncodeFailed)?;
        "image/jpeg"
    };

    Ok(DataUrl {
        mime,
        base64: STANDARD.encode(&buffer),
        width,
        height,
    })
}

/// Whether any pixel is less than fully opaque.
///
/// Asked of the resized image rather than the original, because resampling an image with an alpha
/// channel that happens to be entirely opaque leaves it entirely opaque — so this answers the
/// question that matters (does the stored image need alpha) rather than the one the source's colour
/// type answers (did the source have a channel for it).
fn has_transparency(image: &DynamicImage) -> bool {
    if !image.color().has_alpha() {
        return false;
    }
    image.to_rgba8().pixels().any(|pixel| pixel.0[3] != u8::MAX)
}

#[cfg(test)]
mod tests;
