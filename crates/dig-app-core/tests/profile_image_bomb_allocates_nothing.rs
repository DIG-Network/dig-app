//! A decompression bomb is refused **without allocating what it declared** (dig_ecosystem#3010).
//!
//! # Why this is a separate test binary
//!
//! It installs a `#[global_allocator]`, and a crate may have exactly one. That is also the only
//! instrument that can actually settle the question: every other assertion available — the error
//! variant, the dimensions in the message, the wall-clock time — is equally satisfied by an
//! implementation that allocates fourteen gigabytes and *then* refuses. Only counting the bytes the
//! allocator was asked for distinguishes the bound-on-decode this module claims from a
//! bound-on-output that would leave the machine on its knees first.
//!
//! The declared bitmap is 60,000 x 60,000 RGBA — **14.4 GB**. The ceiling asserted here is 64 MiB,
//! chosen from the fixture rather than from taste: it is over two hundred times the largest thing
//! this test legitimately allocates, and over two hundred times *below* the declared bitmap, so it
//! cannot be passed by accident from either direction.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use dig_app_core::profile_image::{intake, DecodeBounds, IntakeError};

/// Bytes requested from the allocator while [`WATCHING`] is set. Not a live-usage figure: a
/// cumulative total, which is the stricter measure — a decoder that allocated and freed the bomb
/// would still be caught.
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

/// The declared bitmap, in bytes, if the bomb were ever decoded: 60,000 x 60,000 x RGBA.
const DECLARED_BITMAP_BYTES: usize = 60_000 * 60_000 * 4;

/// What intake is allowed to ask the allocator for while refusing the bomb.
const ALLOWED_BYTES: usize = 64 * 1024 * 1024;

#[test]
fn a_bomb_is_refused_without_allocating_its_declared_bitmap() {
    let bomb = bomb_header(60_000, 60_000);
    assert!(bomb.len() < 200, "a bomb is a small file, this one is {}", bomb.len());

    ALLOCATED.store(0, Ordering::Relaxed);
    WATCHING.store(true, Ordering::Relaxed);
    let refusal = intake(&bomb, DecodeBounds::LOCAL_PICK);
    WATCHING.store(false, Ordering::Relaxed);
    let allocated = ALLOCATED.load(Ordering::Relaxed);

    assert!(
        matches!(refusal, Err(IntakeError::TooLarge { .. })),
        "expected a size refusal, got {refusal:?}"
    );
    assert!(
        allocated < ALLOWED_BYTES,
        "refusing a {DECLARED_BITMAP_BYTES} byte declared bitmap allocated {allocated} bytes, \
         over the {ALLOWED_BYTES} this bound permits — the refusal is happening after decode"
    );
}

/// The control. Without it the assertion above is satisfiable by an intake that allocates nothing
/// because it does nothing — the instrument has to be shown capable of seeing an allocation at all.
#[test]
fn the_allocation_counter_can_see_a_real_decode() {
    let real = encoded_png(800, 800);

    ALLOCATED.store(0, Ordering::Relaxed);
    WATCHING.store(true, Ordering::Relaxed);
    let accepted = intake(&real, DecodeBounds::LOCAL_PICK);
    WATCHING.store(false, Ordering::Relaxed);
    let allocated = ALLOCATED.load(Ordering::Relaxed);

    assert!(accepted.is_ok(), "the control image is accepted");
    assert!(
        allocated > 800 * 800,
        "decoding an 800x800 image allocated only {allocated} bytes — the counter is not watching"
    );
}

/// See `profile_image::tests::bomb_header`; duplicated here because a `#[cfg(test)]` helper is not
/// reachable from an integration test binary, and vendoring twenty lines beats widening the crate's
/// public surface with a fixture builder.
fn bomb_header(width: u32, height: u32) -> Vec<u8> {
    let mut bytes = encoded_png(1, 1);
    bytes[16..20].copy_from_slice(&width.to_be_bytes());
    bytes[20..24].copy_from_slice(&height.to_be_bytes());
    let crc = crc32(&bytes[12..29]);
    bytes[29..33].copy_from_slice(&crc.to_be_bytes());
    bytes
}

fn encoded_png(width: u32, height: u32) -> Vec<u8> {
    let image = image::RgbImage::from_fn(width, height, |x, y| {
        image::Rgb([(x % 251) as u8, (y % 241) as u8, ((x ^ y) % 233) as u8])
    });
    let mut bytes = Vec::new();
    image::DynamicImage::ImageRgb8(image)
        .write_to(&mut std::io::Cursor::new(&mut bytes), image::ImageFormat::Png)
        .expect("fixture encodes");
    bytes
}

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
