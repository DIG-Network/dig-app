//! A decompression bomb is refused **without allocating what it declared** (dig_ecosystem#3010).
//!
//! # Why this is a separate test binary
//!
//! It installs a `#[global_allocator]`, and a crate may have exactly one. That is also the only
//! instrument that can settle the question: every other assertion available — the error variant, the
//! dimensions in the message, the wall-clock time — is equally satisfied by an implementation that
//! allocates the whole bitmap and *then* refuses. Only counting the bytes the allocator was asked
//! for distinguishes the bound-on-decode this module claims from a bound-on-output that would leave
//! the machine on its knees first.
//!
//! # Why the fixture is a real bomb and not a bare header
//!
//! A PNG header declaring enormous dimensions with no pixel data behind it is the obvious fixture,
//! and it is a **false green** here: this decoder streams rows, so a header-only file never asks the
//! allocator for the declared bitmap even with every bound removed — the counter reads near zero
//! whether the code is right or wrong, and the test proves nothing. (Measured: with both halves of
//! the bound disabled, a 60,000 x 60,000 header-only fixture still allocated under the ceiling.)
//!
//! So the fixture is an actual decompression bomb — a uniform 6,000 x 6,000 image, which is a few
//! kilobytes compressed and **36 MB** decoded. That is a real allocation, and
//! [`the_counter_sees_the_bomb_when_the_bound_is_raised`] proves the counter sees it: the same bytes,
//! with the bound lifted, blow straight through the ceiling the refusal path stays under.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use dig_app_core::profile_image::{intake, DecodeBounds, IntakeError};

/// Bytes requested from the allocator while [`WATCHING`] is set. Cumulative rather than live usage,
/// which is the stricter measure: a decoder that allocated the bomb and freed it is still caught.
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static WATCHING: AtomicBool = AtomicBool::new(false);

struct CountingAllocator;

// SAFETY: every method forwards to the system allocator unchanged; the counters are the only
// addition and they touch no memory the allocator owns.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if WATCHING.load(Ordering::Relaxed) {
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if WATCHING.load(Ordering::Relaxed) {
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if WATCHING.load(Ordering::Relaxed) && new_size > layout.size() {
            ALLOCATED.fetch_add(new_size - layout.size(), Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// The bomb's side, in pixels.
///
/// Taken from the protocol's own numbers rather than picked for drama: the received path admits
/// 512 x 512, so this is nearly 140x its pixel bound — a size no conforming writer of ours could
/// have produced — while staying small enough that the control below can afford to decode it.
const BOMB_SIDE: u32 = 6_000;

/// What decoding the bomb costs at one byte per pixel, before any RGBA expansion: 36 MB.
const DECODED_BYTES: usize = BOMB_SIDE as usize * BOMB_SIDE as usize;

/// What intake may ask the allocator for while refusing the bomb.
///
/// Taken from the fixture, not from taste: nine times below what decoding costs, and three orders of
/// magnitude above the compressed input, so neither a correct nor a broken implementation lands near
/// it by accident.
const ALLOWED_BYTES: usize = 4 * 1024 * 1024;

#[test]
fn a_bomb_is_refused_without_allocating_its_declared_bitmap() {
    let bomb = uniform_png(BOMB_SIDE, BOMB_SIDE);
    assert!(
        bomb.len() < ALLOWED_BYTES / 8,
        "a bomb is a small file; this fixture is {} bytes and is not one",
        bomb.len()
    );

    // The received path, because that is where a bomb actually arrives: a body some other peer wrote.
    let (refusal, allocated) = watch(|| intake(&bomb, DecodeBounds::RECEIVED));

    assert!(
        allocated < ALLOWED_BYTES,
        "refusing a bomb that decodes to {DECODED_BYTES} bytes allocated {allocated} bytes, over \
         the {ALLOWED_BYTES} this bound permits — the refusal is happening after the decode, not \
         before it"
    );
    assert!(
        matches!(refusal, Err(IntakeError::TooLarge { .. })),
        "expected a size refusal, got {refusal:?}"
    );
}

/// The control that makes the ceiling above mean something.
///
/// Same bytes, bound lifted above the bomb's dimensions: the decode now happens and the counter
/// records it. Without this, "allocated under 8 MiB" is equally satisfied by a counter that is
/// simply not watching, or by a decoder that never allocates for any input.
#[test]
fn the_counter_sees_the_bomb_when_the_bound_is_raised() {
    let bomb = uniform_png(BOMB_SIDE, BOMB_SIDE);
    let lifted = DecodeBounds {
        max_width: BOMB_SIDE,
        max_height: BOMB_SIDE,
        max_pixels: u64::from(BOMB_SIDE) * u64::from(BOMB_SIDE),
        ..DecodeBounds::LOCAL_PICK
    };

    let (accepted, allocated) = watch(|| intake(&bomb, lifted));

    assert!(
        accepted.is_ok(),
        "the lifted bound accepts it: {accepted:?}"
    );
    assert!(
        allocated > ALLOWED_BYTES,
        "decoding the same {DECODED_BYTES} byte bitmap allocated only {allocated} bytes — the \
         counter cannot see this decode, so the refusal test above proves nothing"
    );
}

/// The counter is one global, so only one test may be armed at a time.
///
/// Without this the tests race in a way that reads as a *pass*: the short test finishes first,
/// clears `WATCHING`, and the long one then measures a decode nobody was counting. That is exactly
/// how the control below earned its place — it failed on a near-zero reading while the decode it was
/// measuring was demonstrably running.
static COUNTER: Mutex<()> = Mutex::new(());

/// Run `body` with the allocation counter armed, returning its answer and the bytes it asked for.
fn watch<T>(body: impl FnOnce() -> T) -> (T, usize) {
    let _armed = COUNTER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    ALLOCATED.store(0, Ordering::Relaxed);
    WATCHING.store(true, Ordering::Relaxed);
    let answer = body();
    WATCHING.store(false, Ordering::Relaxed);
    (answer, ALLOCATED.load(Ordering::Relaxed))
}

/// A uniform single-colour PNG — the classic decompression bomb, since a constant image deflates to
/// almost nothing while declaring, and on decode genuinely allocating, its full size.
fn uniform_png(width: u32, height: u32) -> Vec<u8> {
    let image = image::GrayImage::from_pixel(width, height, image::Luma([0u8]));
    let mut bytes = Vec::new();
    image::DynamicImage::ImageLuma8(image)
        .write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .expect("fixture encodes");
    bytes
}

/// **The metadata vector: a colour profile that outweighs the image it describes.**
///
/// The bomb above is a big *picture*. This one is a 1x1 picture carrying a big *colour profile*, and
/// it is the case every other bound in the module misses: `max_input_bytes` bounds the COMPRESSED
/// file, and the width/height/pixel checks read an IHDR that honestly says 1x1. Nothing in the
/// module's own arithmetic can see it.
///
/// It reaches the allocator because reading a PNG "header" is not header-only — `into_dimensions()`
/// builds the full decoder, which walks every ancillary chunk ahead of IDAT, and `iCCP` carries a
/// zlib-compressed profile that png decompresses on the way past with a budget taken from the limits
/// it was handed.
///
/// **Refusal is not the assertion here, and that is the point.** With the bound in place png skips
/// the chunk it cannot afford and returns the honest 1x1 image — a success, not an error. So an
/// error-shaped test would fail on correct code, and a "did it decode?" test passes on broken code.
/// Only the allocator distinguishes them.
#[test]
fn a_compressed_colour_profile_cannot_outgrow_the_decode_it_precedes() {
    const DECLARED: usize = 64 * 1024 * 1024;

    let bomb = iccp_bomb(DECLARED);
    assert!(
        bomb.len() < DecodeBounds::RECEIVED.max_input_bytes,
        "the fixture must be legal by size or it is refused for the wrong reason: {} bytes",
        bomb.len()
    );

    let (outcome, allocated) = watch(|| intake(&bomb, DecodeBounds::RECEIVED));

    // Measured against what the attacker DECLARED, not against a fixed ceiling. The bound does not
    // promise "allocates nothing" — png still spends its allowance discovering the chunk is
    // unaffordable, and the decode that follows needs real buffers. What it promises is that the
    // spend tracks OUR limits rather than the attacker's number. Measured: about 4.7 MB against
    // 64 MiB declared, and it stays flat as DECLARED grows, which is the property that matters.
    let ceiling = DECLARED / 8;
    assert!(
        allocated < ceiling,
        "a {DECLARED}-byte colour profile on a 1x1 image drew {allocated} bytes through the \
         allocator; the bound should hold that far under {ceiling}"
    );
    // The image itself is honest and tiny, so it is served rather than refused. Asserted so a future
    // change that starts REFUSING these is noticed as a behaviour change rather than passing quietly.
    assert!(
        outcome.is_ok(),
        "the 1x1 image behind the profile was refused: {outcome:?}"
    );
}

/// The counter sees this bomb too when the bound is lifted — the control for the test above.
///
/// Without it, `a_compressed_colour_profile_cannot_outgrow_the_decode_it_precedes` is satisfied by a
/// decoder that never allocates for any reason, which is exactly the false green that the
/// header-only fixture turned out to be.
#[test]
fn the_counter_sees_the_colour_profile_when_it_is_decompressed() {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    const DECLARED: usize = 64 * 1024 * 1024;
    let bomb = iccp_bomb(DECLARED);

    // Decompress the same payload directly: this is what png does on the unbounded path, and it is
    // the allocation the bound prevents.
    let start = bomb
        .windows(4)
        .position(|w| w == b"iCCP")
        .expect("the fixture carries an iCCP chunk");
    let length = u32::from_be_bytes(bomb[start - 4..start].try_into().unwrap()) as usize;
    let payload = &bomb[start + 4..start + 4 + length];
    let compressed = &payload[3..]; // past "p\0" and the compression-method byte

    let (decompressed, allocated) = watch(|| {
        let mut out = Vec::new();
        ZlibDecoder::new(compressed)
            .read_to_end(&mut out)
            .expect("the profile decompresses");
        out.len()
    });

    assert_eq!(decompressed, DECLARED);
    assert!(
        allocated > ALLOWED_BYTES,
        "the counter did not see a {DECLARED}-byte decompression: {allocated} bytes"
    );
}

/// A 1x1 PNG carrying an `iCCP` chunk whose colour profile decompresses to `declared` bytes.
fn iccp_bomb(declared: usize) -> Vec<u8> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(&vec![0u8; declared])
        .expect("zeros compress");
    let compressed = encoder.finish().expect("the stream closes");

    // iCCP payload: null-terminated profile name, the compression-method byte (0 = zlib), then the
    // compressed profile.
    let mut payload = b"p\0\0".to_vec();
    payload.extend_from_slice(&compressed);

    let mut chunk = (payload.len() as u32).to_be_bytes().to_vec();
    chunk.extend_from_slice(b"iCCP");
    chunk.extend_from_slice(&payload);
    chunk.extend_from_slice(&crc32(&chunk[4..]).to_be_bytes());

    // Spliced right after IHDR (8-byte signature + 25-byte IHDR chunk) so it is read before any
    // pixel data — where a real encoder would put it.
    let base = uniform_png(1, 1);
    let mut bytes = base[..33].to_vec();
    bytes.extend_from_slice(&chunk);
    bytes.extend_from_slice(&base[33..]);
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
