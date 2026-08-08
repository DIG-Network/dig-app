//! Open ONE content pane, at a chosen tab, size and theme, so it can be photographed.
//!
//! # Why this exists beside `shell_gallery`
//!
//! The shell gallery opens the real window, which opens on `Status`; reaching any other tab means
//! clicking a chip. A committed screenshot must not be taken after synthetic input
//! (dig_ecosystem#2309 records what that costs — the click stole foreground and the capture was of
//! the window behind), so photographing the Apps or Settings tab needed a way to open ON that tab.
//!
//! This is that way. It draws the same pane the shell draws, from the same model and facts, with the
//! tab as a parameter instead of as state.
//!
//! ```text
//! cargo run -p dig-app-core --example pane_preview -- settings light 960 640
//! cargo run -p dig-app-core --example pane_preview -- apps dark 480 480
//! ```
//!
//! Sizes are LOGICAL pixels; the display's scaling is applied by the windowing system, so a capture
//! on a 2.5× display is 2.5× larger and must be labelled with both figures.
//!
//! This example only ever DRAWS. A click is read and discarded — a verb dispatched from a gallery
//! would run against the machine it is previewing on.

use dig_app_core::cache::{CacheSnapshot, GIB, MIB};
use dig_app_core::confirm::gui::{open_pane_preview, preview_theme};
use dig_app_core::tray_menu::{AccountState, TrayView, WindowHost};
use dig_app_core::window_model::TabId;

/// The view every pane is photographed against: the richest state, so nothing reads as empty by
/// accident.
///
/// The beacon is deliberately present and HEALTHY here; the other beacon states are photographed by
/// the `--beacon` argument below, because "what this looks like when the updater cannot be asked" is
/// exactly the picture worth having.
fn preview_view(beacon: Beacon) -> TrayView {
    TrayView {
        running: true,
        node_connected: true,
        node: "Node v0.65.0 · 3 capsule(s) cached · 1 store(s) hosted".to_string(),
        account: Some(AccountState::Unlocked { recoverable: true }),
        receive_address: Some(
            "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln".to_string(),
        ),
        second_factor: true,
        window_host: WindowHost::Available,
        cache: Some(CacheSnapshot {
            cap_bytes: GIB,
            used_bytes: 350 * MIB,
        }),
        update: beacon.status(),
        ..TrayView::default()
    }
}

/// Which beacon state to photograph.
#[derive(Clone, Copy)]
enum Beacon {
    /// Updates running, on the stable feed.
    Live,
    /// The daily schedule was removed: updates are OFF even though nothing is paused.
    OptedOut,
    /// The updater could not be asked at all — the state where the controls must disappear.
    Absent,
}

impl Beacon {
    fn status(self) -> Option<dig_app_core::auto_update::BeaconStatus> {
        use dig_app_core::auto_update::{BeaconStatus, UpdateChannel};
        match self {
            Self::Live => Some(BeaconStatus {
                paused: false,
                schedule_opted_out: false,
                channel: UpdateChannel::Stable,
            }),
            Self::OptedOut => Some(BeaconStatus {
                paused: false,
                schedule_opted_out: true,
                channel: UpdateChannel::Nightly,
            }),
            Self::Absent => None,
        }
    }

    fn parse(name: &str) -> Option<Self> {
        match name {
            "live" => Some(Self::Live),
            "opted-out" => Some(Self::OptedOut),
            "absent" => Some(Self::Absent),
            _ => None,
        }
    }
}

/// Every tab the preview can open, by the name given on the command line.
fn tab(name: &str) -> Option<TabId> {
    match name {
        "status" => Some(TabId::Status),
        "account" => Some(TabId::Account),
        "security" => Some(TabId::Security),
        "wallet" => Some(TabId::Wallet),
        "apps" => Some(TabId::Apps),
        "cache" => Some(TabId::Cache),
        "settings" => Some(TabId::Settings),
        _ => None,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: pane_preview <tab> <light|dark> [width] [height] [live|opted-out|absent]";

    let Some(tab) = args.first().and_then(|name| tab(name)) else {
        eprintln!("{usage}");
        std::process::exit(2);
    };
    let Some(theme) = args.get(1).map(String::as_str).and_then(preview_theme) else {
        eprintln!("{usage}");
        std::process::exit(2);
    };
    let size = (
        args.get(2).and_then(|w| w.parse().ok()).unwrap_or(960.0),
        args.get(3).and_then(|h| h.parse().ok()).unwrap_or(640.0),
    );
    let Some(beacon) = Beacon::parse(args.get(4).map(String::as_str).unwrap_or("live")) else {
        eprintln!("{usage}");
        std::process::exit(2);
    };

    println!("previewing {tab:?} at {size:?} logical px; close the window when you are done");
    if let Err(why) = open_pane_preview(theme, tab, size, preview_view(beacon)) {
        eprintln!("{why}");
        std::process::exit(1);
    }
}
