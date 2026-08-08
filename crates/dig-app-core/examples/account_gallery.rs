//! Raise the real DIG app window in ONE chosen account state, so the Account and Security panes can
//! be looked at in every state they are reachable in.
//!
//! # Why a second gallery
//!
//! [`shell_gallery`](../shell_gallery.rs) photographs the RICHEST view — an unlocked, recoverable
//! account on a connected node — which is the right default for asking whether the busiest tab reads
//! well. It is the wrong tool for these two panes, because their whole job is the six account states
//! and five of them are not that one. dig_ecosystem#2059 was a defect in three states at once,
//! invisible from a screenshot of the sixth.
//!
//! ```text
//! cargo run -p dig-app-core --example account_gallery -- light needs-password
//! cargo run -p dig-app-core --example account_gallery -- dark unopenable
//! ```
//!
//! The first argument is the theme, the second the account state (`unsupported`, `absent`, `locked`,
//! `unopenable`, `needs-password`, `unlocked`, `unlocked-no-phrase`). The window stays up until it is
//! closed, and this example only ever DRAWS: it raises no prompt, and nothing here reaches a chain, a
//! key or a wallet.
//!
//! # The one thing this cannot do yet
//!
//! The window opens on the tab `shell.rs` names `FIRST_TAB`, and nothing else selects a tab, so
//! reaching Account or Security means a person clicking one. A capture harness must NOT click for
//! them — synthetic input takes the foreground off the window and photographs whatever was behind it
//! — so an unattended capture of these two panes needs `AppWindow` to carry the tab to open on.
//! That is a change in `shell.rs`, which Phase 2 lanes report rather than make
//! (dig_ecosystem#2326).

use std::sync::Arc;

use dig_app_core::cache::{CacheSnapshot, GIB, MIB};
use dig_app_core::confirm::gui::{open_app_window, AppWindow, Theme, ThemeChoice};
use dig_app_core::tray_menu::{AccountState, TrayView, WindowHost};
use dig_app_core::window_model::TabId;

/// The account state named by `argument`, or `None` when it names nothing.
///
/// Every variant is reachable here, including both unlocked ones: `recoverable` decides which
/// management verbs the model offers, so an account with no recovery phrase draws a different
/// Account pane from one that has it.
fn account_state(argument: &str) -> Option<AccountState> {
    match argument {
        "unsupported" => Some(AccountState::Unsupported),
        "absent" => Some(AccountState::Absent),
        "locked" => Some(AccountState::Locked),
        "unopenable" => Some(AccountState::Unopenable),
        "needs-password" => Some(AccountState::NeedsPassword),
        "unlocked" => Some(AccountState::Unlocked { recoverable: true }),
        "unlocked-no-phrase" => Some(AccountState::Unlocked { recoverable: false }),
        _ => None,
    }
}

/// Match the tray's DPI posture, so a screenshot taken here is what the user actually sees.
///
/// Without it Windows DPI-virtualises this process and the gallery renders the 100% layout on a
/// scaled display — a preview that quietly disagrees with the thing it previews.
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

/// The view to draw: one account state, on a machine that is otherwise working.
///
/// Everything around the account is held FIXED across the states so that what changes between two
/// captures is the account and nothing else. A second factor is enrolled, because that is the state
/// in which the Security pane has a control to show on its second-factor line — the case where it
/// has none is reached by `locked` and `needs-password`, where the model offers no row at all.
fn view_for(account: AccountState, second_factor: bool) -> TrayView {
    TrayView {
        running: true,
        node_connected: true,
        node: "Node v0.65.0 · 3 capsule(s) cached · 1 store(s) hosted".to_string(),
        account: Some(account),
        profile_id: Some(
            "4f3a9c2e7b81d05fa6c34e19b7d208fc5e6a1b93d47f0c28ae5b6139d0f7a24c".to_string(),
        ),
        receive_address: Some(
            "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln".to_string(),
        ),
        second_factor,
        window_host: WindowHost::Available,
        cache: Some(CacheSnapshot {
            cap_bytes: GIB,
            used_bytes: 350 * MIB,
        }),
        ..TrayView::default()
    }
}

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
    let named = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "unlocked".to_string());
    let Some(account) = account_state(&named) else {
        eprintln!(
            "unknown account state `{named}` — expected one of unsupported, absent, locked, \
             unopenable, needs-password, unlocked, unlocked-no-phrase"
        );
        std::process::exit(2);
    };
    // Off by default so the Security pane's no-control second-factor line is what a plain run shows:
    // it is the case the design brief singles out, and the one an invented disabled button would
    // have hidden.
    let second_factor = std::env::args().any(|argument| argument == "--second-factor");

    // The HOST's own store, not a temp one, so the shell reads the real preference — exactly what
    // clicking the theme toggle does — and it is put back on the way out.
    let store = ThemeChoice::for_host();
    let previous = store.read();
    store.write(theme).expect("the theme preference is written");

    let opened = open_app_window(AppWindow {
        theme: store,
        view: Arc::new(move || view_for(account.clone(), second_factor)),
        // A gallery DRAWS; it does not act. Printing the verb is what makes a click legible in the
        // terminal beside the screenshot, and it is the honest thing for an example with no worker
        // and no account behind it to do.
        act: Arc::new(|action| println!("a row was clicked: {action:?}")),
        // The whole point of this gallery: open ON the tab being photographed, so a capture needs no
        // click. A harness that clicks to set up a shot eventually photographs whatever was actually
        // on screen — which is how a committed "Cache" screenshot turned out to be the Status tab.
        initial_tab: Some(TabId::Account),
    });
    let _ = ThemeChoice::for_host().write(previous);

    if !opened {
        eprintln!("this host cannot draw the DIG app window");
        std::process::exit(1);
    }

    // `open_app_window` hands the window to its own thread and returns, so main returning here would
    // take the process — and the window — down with it before anyone could look at either.
    println!("{theme:?} · {named} · second factor {second_factor}; open for {HOLD_OPEN:?}");
    std::thread::sleep(HOLD_OPEN);
}

/// How long the window is held open: long enough to photograph every tab at both widths, and
/// bounded so a forgotten gallery does not outlive the session that started it.
const HOLD_OPEN: std::time::Duration = std::time::Duration::from_secs(600);
