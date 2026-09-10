//! Photograph the Content tab's Rewards section in each of its four states (dig_ecosystem#3273).
//!
//! ```text
//! cargo run -p dig-app-core --example store_rewards_gallery -- docs/gallery/store-rewards
//! ```
//!
//! One file per state — `waiting`, `not-answerable`, `unreachable`, `empty`, `ready` — written by
//! [`dig_app_core::confirm::gui::photograph_shell`], which reads the real framebuffer back with
//! `egui::ViewportCommand::Screenshot`. That matters: GDI (`PrintWindow`, `BitBlt`, every
//! screenshot tool built on them) is blind to a hardware GL surface and returns a black rectangle
//! of exactly the right size, so a capture taken with a screenshot tool would look plausible and
//! be evidence of nothing. The scale is PINNED inside `photograph_shell`, so these files are the
//! same pixel dimensions on every machine.
//!
//! Nothing is clicked. The section is collapsed by default and its reading comes from a node, so
//! both are planted before the first frame through
//! [`dig_app_core::confirm::gui::CaptureStaging::rewards`] — a committed screenshot must never be
//! taken after synthetic input (dig_ecosystem#2309).
//!
//! # What the READY capture's figures are
//!
//! A fixture, stated as one. No dig-node released today answers
//! `dig.listRewardDistributors`, so a live distributor cannot be reached to photograph; the record
//! is built inside `dig-app-core` and rendered by the SHIPPING formatter, which is the part a
//! picture is evidence about. This example reaches no chain, no key and no wallet, and raises no
//! prompt.

use std::sync::Arc;

use dig_app_core::cache::{CacheSnapshot, GIB, MIB};
use dig_app_core::confirm::gui::{photograph_shell, CaptureStaging, RewardsPreview, Theme};
use dig_app_core::hosted_stores::{HostedStore, HostedStoresReading};
use dig_app_core::tray_menu::{AccountState, TrayView, WindowHost};
use dig_app_core::window_model::TabId;

/// The store the section hangs off. A real 64-hex id, at the length a person actually sees it, so
/// the capture shows how the row and the section below it share the column.
const STORE_ID: &str = "3f9a1c0b7e2d48561a0c9f3b8d47e25610fa3c9b2e5d704816af39c2b0d5e871";

/// Every state, and the name a capture of it is filed under.
///
/// Listed here rather than in `dig-app-core` because a `slug` inside the crate would have no caller
/// in the headless build, and an `#[allow(dead_code)]` to quiet that is how a function nobody calls
/// starts looking deliberate. Exhaustive over [`RewardsPreview`]: a fifth state cannot be added
/// upstream without this array failing to name it.
const CAPTURES: [(RewardsPreview, &str); 5] = [
    (RewardsPreview::Waiting, "waiting"),
    // The state a real install shows today, on every store row: no released dig-node serves the
    // read that maps a store to a distributor. A capture set that skipped it would picture four
    // states nobody can reach and none of the one everybody sees (dig_ecosystem#3273 adversarial
    // gate, finding 5).
    (RewardsPreview::NotAnswerable, "not-answerable"),
    (RewardsPreview::Unreachable, "unreachable"),
    (RewardsPreview::Empty, "empty"),
    (RewardsPreview::Ready, "ready"),
];

/// The window size every capture is taken at, in logical points.
///
/// The width is the default window rather than `SHELL_MIN`: the section's own wrapping at the
/// narrow width is what the unit tests measure, and a gallery photographing only the narrow case
/// would show every sentence at its worst line count.
///
/// # Why the height is this tall, and how it was chosen
///
/// A capture is evidence ONLY of what is inside the frame. At 900 points the `ready` frame cut off
/// after the second of four sentences: `rewards-paid-out-total` — the one $DIG figure on this
/// surface — and the cadence sentence finding 1 was about both fell off the bottom, which is how
/// that defect survived three review legs and a human inspection. A frame that cuts mid-content
/// looks identical to a frame that ends because the content ended (dig_ecosystem#3273 adversarial
/// gate, finding 2).
///
/// So the height is set past the point where the section CLOSES: the card's own bottom border sits
/// below the last sentence in every one of the five files, which is the element that proves nothing
/// was cut. Raise this rather than crop if a sentence is ever added to the section.
const SIZE: (f32, f32) = (960.0, 1240.0);

/// The Content tab as a node that is answering would present it: a real cache figure, one hosted
/// store, and nothing else claimed.
fn view() -> TrayView {
    TrayView {
        running: true,
        node_connected: true,
        node: "Node v0.256.0 · 3 capsule(s) cached · 1 store(s) hosted".to_string(),
        account: Some(AccountState::Unlocked { recoverable: true }),
        second_factor: dig_app_core::account::second_factor::vault::EnrolmentState::Enrolled,
        window_host: WindowHost::Available,
        cache: Some(CacheSnapshot {
            cap_bytes: GIB,
            used_bytes: 350 * MIB,
        }),
        hosted_stores: HostedStoresReading::Known(vec![HostedStore {
            store_id: STORE_ID.to_string(),
            pinned: true,
            capsule_count: 3,
            total_bytes: 41 * MIB,
        }]),
        // A fixture takes no reading (dig_ecosystem#2398).
        mint_chain: None,
        ..TrayView::default()
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let directory = args.first().map(String::as_str).unwrap_or(".");
    if let Err(problem) = std::fs::create_dir_all(directory) {
        eprintln!("{directory} could not be created: {problem}");
        std::process::exit(1);
    }

    // Every state in one loop rather than four call sites, so a capture set cannot come out
    // missing one — a set missing a state is how the state that matters ends up unphotographed.
    for (which, slug) in CAPTURES {
        let path = std::path::Path::new(directory)
            .join(format!("content-store-rewards-{slug}-light-960.png"));
        match photograph_shell(
            Theme::Light,
            TabId::Content,
            egui::Vec2::new(SIZE.0, SIZE.1),
            Arc::new(view),
            &path,
            CaptureStaging {
                editing: None,
                offer: None,
                dragging: None,
                dropping: None,
                looking_up: None,
                rewards: Some((STORE_ID.to_string(), which)),
            },
        ) {
            Ok((pixels_wide, pixels_high)) => {
                println!("{} — {pixels_wide} x {pixels_high} px", path.display());
            }
            Err(problem) => {
                eprintln!("{} was not written: {problem}", path.display());
                std::process::exit(1);
            }
        }
    }
}
