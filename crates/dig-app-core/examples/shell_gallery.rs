//! Raise the real, OS-drawn DIG app window so a human can LOOK at it.
//!
//! # Why this exists
//!
//! Same reason as [`dialog_gallery`](../dialog_gallery.rs): the things that go wrong on this surface
//! go wrong in the presentation the operating system draws, where no unit test can see them. The
//! headless suite pins every RULE the shell host follows — what is admitted, what is dismissed, what
//! is refused — and none of it can tell you whether the scrim reads as inert, or whether a modal
//! centred over a scrimmed pane reads as the one thing on screen that wants an answer.
//!
//! Since dig_ecosystem#2270 the prompt is drawn INSIDE this window rather than as a second one, so
//! this is also the only place the two surfaces can be compared by eye: the modal here and the
//! standalone window in `dialog_gallery` are painted by the same code and must look it.
//!
//! ```text
//! cargo run -p dig-app-core --example shell_gallery -- light
//! cargo run -p dig-app-core --example shell_gallery -- dark 90   # raise the prompt after 90s
//! ```
//!
//! The window opens alone, and after [`PROMPT_AFTER`] — overridable by the second argument, in
//! seconds — a real consent prompt is raised over it, so one run photographs both states. The
//! override exists because photographing the six tabs takes longer than the default delay, and a
//! scrimmed tab is a picture of the scrim rather than of the tab. Escape denies the prompt while it is up, and closes the window once it is gone. This example only ever DRAWS — the prompt it raises is a `sign` confirm whose answer is
//! printed and discarded, and nothing here reaches a chain, a key or a wallet.

use std::time::Duration;

use std::sync::Arc;

use dig_app_core::cache::{CacheSnapshot, GIB, MIB};
use dig_app_core::confirm::gui::{open_app_window, AppWindow, Theme, ThemeChoice};
use dig_app_core::confirm::{native_confirmer, SignPrompt};
use dig_app_core::tray_menu::{AccountState, TrayView, WindowHost};

/// How long the shell is left alone before a prompt is raised over it — long enough to photograph
/// the unscrimmed window first.
const PROMPT_AFTER: Duration = Duration::from_secs(6);

/// How long to wait before raising the prompt, honouring the optional second argument.
fn prompt_after() -> Duration {
    match std::env::args().nth(2).map(|raw| raw.parse::<u64>()) {
        Some(Ok(seconds)) => Duration::from_secs(seconds),
        Some(Err(_)) => {
            eprintln!("the second argument is a delay in whole seconds");
            std::process::exit(2);
        }
        None => PROMPT_AFTER,
    }
}

/// How long the process stays alive after that, so the scrimmed state can be photographed too.
const THEN_WAIT: Duration = Duration::from_secs(120);

/// Match the tray's DPI posture, so a screenshot taken here is what the user actually sees.
///
/// `dig-app` is per-monitor DPI-aware because tao sets that when it builds the tray. This example
/// has no tao, so without this call Windows DPI-virtualises it and the gallery would render the 100%
/// layout on a scaled display — a preview that quietly disagrees with the thing it previews.
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

/// The view the gallery photographs: an unlocked, recoverable account on a connected node.
///
/// The RICHEST state on purpose. A screenshot of a default view would show mostly-empty panes and
/// would not answer the question a gallery exists to answer — whether the busiest tab still reads
/// well. The narrow and empty states are photographed by resizing the window and by the states the
/// headless suite covers.
fn gallery_view() -> TrayView {
    TrayView {
        running: true,
        node_connected: true,
        node: "Node v0.65.0 · 3 capsule(s) cached · 1 store(s) hosted".to_string(),
        account: Some(AccountState::Unlocked { recoverable: true }),
        profile_id: Some("dig1qqqqexamplepublicidentitykeyforthegalleryonly".to_string()),
        receive_address: Some(
            "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln".to_string(),
        ),
        second_factor: true,
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

    // The HOST's own store, not a temp one, so the shell and the prompt raised over it read the
    // same preference and a paired screenshot cannot show two different themes at once. This writes
    // the real preference file — exactly what clicking the theme toggle in the app does — and puts
    // it back on the way out.
    let store = ThemeChoice::for_host();
    let previous = store.read();
    store.write(theme).expect("the theme preference is written");

    if !open_app_window(AppWindow {
        theme: store,
        view: Arc::new(gallery_view),
        // A gallery DRAWS; it does not act. Printing the verb is what makes a click legible in the
        // terminal beside the screenshot, and it is the honest thing for an example with no worker
        // and no account behind it to do.
        act: Arc::new(|action| println!("a row was clicked: {action:?}")),
    }) {
        eprintln!("this host cannot draw the DIG app window");
        std::process::exit(1);
    }
    let delay = prompt_after();
    println!("the app window is open ({theme:?}); a prompt follows in {delay:?}");

    std::thread::sleep(delay);

    // Raised from a worker exactly as a real request is: `show` blocks until the person answers, so
    // calling it on the thread that drew the window would be the deadlock the host design forbids.
    let raiser = std::thread::spawn(|| {
        let decision = native_confirmer().confirm_sign(&SignPrompt {
            origin: "https://dapp.example",
            payload_type: "spend",
            decoded_tx: Some("Send 0.001 XCH to xch1safe\u{2026}addr"),
        });
        println!("prompt answered: {decision:?}");
    });

    println!("photograph the scrim and the pill now; the window stays up for {THEN_WAIT:?}");
    std::thread::sleep(THEN_WAIT);
    let _ = raiser.join();
    let _ = ThemeChoice::for_host().write(previous);
}
