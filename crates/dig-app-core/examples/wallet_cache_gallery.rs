//! Raise the real, OS-drawn DIG app window in one chosen Wallet or Cache state, so a human can LOOK
//! at it.
//!
//! # Why a second gallery rather than an argument to `shell_gallery`
//!
//! `shell_gallery` photographs the RICHEST snapshot, which is the right default and is exactly why it
//! cannot show these: the states that ship broken on a money surface are the ones where a figure is
//! MISSING. A balance still being read, a node that did not answer in time, a locked account, a cache
//! reporting bytes with nothing mirrored yet — each is a different `TrayView`, and none of them can be
//! reached by resizing the rich one.
//!
//! ```text
//! cargo run -p dig-app-core --example wallet_cache_gallery -- light rich
//! cargo run -p dig-app-core --example wallet_cache_gallery -- dark timed-out
//! ```
//!
//! The window opens and stays up for [`STAY`]; Escape closes it. This example only ever DRAWS —
//! nothing here reaches a chain, a key or a wallet, and a click prints the verb and discards it.

use std::sync::Arc;
use std::time::Duration;

use dig_app_core::cache::{CacheSnapshot, GIB, MIB};
use dig_app_core::confirm::gui::{open_app_window, AppWindow, Theme, ThemeChoice};
use dig_app_core::tray_menu::{AccountState, TrayView, WindowHost};
use dig_app_core::wallet::overview::{BalanceReading, BalanceUnknown, Balances};

/// How long the window stays up, so a capture can resize it and photograph both widths.
const STAY: Duration = Duration::from_secs(240);

/// The receive address the gallery shows. A real mainnet-shaped address, because the QR block's whole
/// job is to encode one of these and a shorter stand-in would produce a smaller code than ships.
const ADDRESS: &str = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";

/// The cache figures read off a live machine: a 10 GiB limit with 407 MB in it.
fn live_cache() -> CacheSnapshot {
    CacheSnapshot {
        cap_bytes: 10 * GIB,
        used_bytes: 407 * MIB,
    }
}

/// The base snapshot every case varies: an unlocked account on a connected node.
fn unlocked() -> TrayView {
    TrayView {
        running: true,
        node_connected: true,
        node: "Node v0.65.0 · 3 capsule(s) cached · 3 store(s) hosted · 2 pinned".to_string(),
        account: Some(AccountState::Unlocked { recoverable: true }),
        receive_address: Some(ADDRESS.to_string()),
        second_factor: true,
        window_host: WindowHost::Available,
        cache: Some(live_cache()),
        ..TrayView::default()
    }
}

/// The states this gallery can photograph.
///
/// Every one is a state a real user reaches. They are named on the command line rather than cycled,
/// so a screenshot's filename and its fixture cannot drift apart.
fn case(name: &str) -> Option<TrayView> {
    Some(match name {
        // Both figures read: the only case in which this window shows a numeral for money.
        "rich" => TrayView {
            balance: BalanceReading::Known(Balances {
                xch_mojos: 1_250_000_000_000,
                dig_units: 4_200_500,
            }),
            ..unlocked()
        },
        // The state that is on screen for 2.5–6 seconds on every open (dig_ecosystem#2325).
        "pending" => TrayView {
            balance: BalanceReading::Pending,
            ..unlocked()
        },
        // A node that connected and did not finish the read — NOT an absent node, which is the
        // distinction a live user was shown wrongly.
        "timed-out" => TrayView {
            balance: BalanceReading::Unknown(BalanceUnknown::NodeTimedOut),
            ..unlocked()
        },
        // Sealed: no address to show, so no code and no figure, and the card explains which.
        "locked" => TrayView {
            account: Some(AccountState::Locked),
            receive_address: None,
            ..unlocked()
        },
        // The cache trap: real bytes on disk, nothing finished syncing.
        "cache-bytes" => TrayView {
            balance: BalanceReading::Known(Balances {
                xch_mojos: 0,
                dig_units: 0,
            }),
            ..unlocked()
        },
        // No node: the Cache tab's own error state, where neither figure can be read.
        "no-node" => TrayView {
            node_connected: false,
            node: "Looking for a DIG node…".to_string(),
            cache: None,
            balance: BalanceReading::Unknown(BalanceUnknown::NoNode),
            ..unlocked()
        },
        _ => return None,
    })
}

/// Match the tray's DPI posture, so a screenshot taken here is what the user actually sees.
#[cfg(windows)]
fn match_the_trays_dpi_awareness() {
    // SAFETY: a documented, idempotent process-wide call with a constant argument; a failure (an
    // older Windows, or awareness already set) is reported by the return value and is harmless.
    unsafe {
        let _ = windows::Win32::UI::HiDpi::SetProcessDpiAwarenessContext(
            windows::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        );
    }
}

#[cfg(not(windows))]
fn match_the_trays_dpi_awareness() {}

fn main() {
    match_the_trays_dpi_awareness();

    let theme = match std::env::args().nth(1).as_deref() {
        Some("dark") => Theme::Dark,
        Some("light") | None => Theme::Light,
        Some(other) => {
            eprintln!("unknown theme `{other}` — expected light or dark");
            std::process::exit(2);
        }
    };
    let name = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "rich".to_string());
    let Some(view) = case(&name) else {
        eprintln!(
            "unknown case `{name}` — expected rich, pending, timed-out, locked, cache-bytes or \
             no-node"
        );
        std::process::exit(2);
    };

    // The HOST's own store, exactly as `shell_gallery` does it, so the window and any prompt raised
    // over it cannot show two different themes — and it is put back on the way out.
    let store = ThemeChoice::for_host();
    let previous = store.read();
    store.write(theme).expect("the theme preference is written");

    if !open_app_window(AppWindow {
        theme: store,
        view: Arc::new(move || view.clone()),
        act: Arc::new(|action| println!("a row was clicked: {action:?}")),
    }) {
        eprintln!("this host cannot draw the DIG app window");
        std::process::exit(1);
    }
    println!("the app window is open ({theme:?}, case {name}); it stays up for {STAY:?}");
    std::thread::sleep(STAY);
    let _ = ThemeChoice::for_host().write(previous);
}
