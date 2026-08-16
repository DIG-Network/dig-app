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
