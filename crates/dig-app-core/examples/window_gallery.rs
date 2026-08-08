//! Photograph the REAL DIG app window on a chosen tab, theme, size and account state.
//!
//! # Why this and not `pane_preview`
//!
//! [`pane_preview`](../pane_preview.rs) draws a pane and deliberately leaves out the shell's chrome.
//! That is the right instrument for asking whether one pane reads well, and the wrong one for asking
//! what the application looks like: the sidebar, the title row and the close affordance are most of
//! what a person sees, and at the shell's minimum width they are where the layout is under the most
//! pressure. A gallery of panes is not a picture of the app.
//!
//! This drives the shipping shell through its own paint path and writes a PNG.
//!
//! ```text
//! cargo run -p dig-app-core --features gui --example window_gallery -- \
//!     account light 480 900 locked docs/gallery/account-light-480.png
//! ```
//!
//! # Nothing is clicked, and nothing is screen-captured
//!
//! Reaching the fourth tab, or a 480 px window, by clicking and dragging is what a capture harness
//! must never do: synthetic input takes the foreground off the window and photographs whatever was
//! behind it — which is how a committed screenshot labelled "Cache" turned out to be the Status tab
//! (dig_ecosystem#2326). Every axis that used to need input is an ARGUMENT here.
//!
//! The capture itself is a framebuffer readback rather than a screen grab, because GDI is blind to a
//! hardware GL surface and hands back a black rectangle of exactly the right size — a failure that
//! reports success. See `photograph_shell`.
//!
//! # Why every account state is reachable
//!
//! The Account and Security panes exist to express the six account states, and five of them are not
//! the rich one. dig_ecosystem#2059 was a defect in three states at once, invisible from a
//! screenshot of the sixth.
//!
//! This example only ever DRAWS: it raises no prompt, and nothing here reaches a chain, a key or a
//! wallet.

use std::sync::Arc;

use dig_app_core::cache::{CacheSnapshot, GIB, MIB};
use dig_app_core::confirm::gui::{photograph_shell, Theme};
use dig_app_core::tray_menu::{AccountState, TrayView, WindowHost};
use dig_app_core::wallet::overview::{BalanceReading, Balances};
use dig_app_core::window_model::TabId;

/// The tab named by `argument`, or `None` when it names nothing.
fn tab(argument: &str) -> Option<TabId> {
    TabId::all().into_iter().find(|tab| name(*tab) == argument)
}

/// The command-line name of a tab — its label, lowercased.
///
/// Derived rather than listed, so the gallery cannot come to disagree with the window about which
/// tabs exist: the old hand-written match still accepted `status`, `security`, `apps` and `cache`
/// long after those tabs were merged away (dig_ecosystem#2358), which is how a file lands under a
/// name that describes a picture nobody can take.
fn name(tab: TabId) -> String {
    format!("{tab:?}").to_lowercase()
}

/// The account state named by `argument`, or `None` when it names nothing.
///
/// Every variant is reachable, including both unlocked ones: `recoverable` decides which management
/// verbs the model offers, so an account with no recovery phrase draws a different Account pane from
/// one that has it.
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

/// The balance the gallery shows: 12.5 $DIG and 0.25 XCH, in each asset's own base unit.
///
/// Written in base units rather than as decimals, because that is what the type holds and what the
/// pane's one formatter divides — a gallery that pre-divided would photograph a figure the
/// application does not produce.
const HELD: Balances = Balances {
    dig_units: 12_500,
    xch_mojos: 250_000_000_000,
};

/// The view to draw: one account state, on a machine that is otherwise working.
///
/// Everything around the account is held FIXED across the states, so what changes between two
/// captures is the account and nothing else. A sealed account has no key to derive an address from,
/// so it gets no address, no profile id and no balance — a gallery that showed them anyway would
/// photograph figures the application cannot produce in that state.
fn view_for(account: AccountState, second_factor: bool) -> TrayView {
    let sealed = !matches!(account, AccountState::Unlocked { .. });
    TrayView {
        running: true,
        node_connected: true,
        node: "Node v0.65.0 · 3 capsule(s) cached · 1 store(s) hosted".to_string(),
        account: Some(account),
        profile_id: (!sealed).then(|| {
            "4f3a9c2e7b81d05fa6c34e19b7d208fc5e6a1b93d47f0c28ae5b6139d0f7a24c".to_string()
        }),
        receive_address: (!sealed)
            .then(|| "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln".to_string()),
        balance: match sealed {
            true => BalanceReading::default(),
            false => BalanceReading::Known(HELD),
        },
        second_factor,
        window_host: WindowHost::Available,
        cache: Some(CacheSnapshot {
            cap_bytes: GIB,
            used_bytes: 350 * MIB,
        }),
        ..TrayView::default()
    }
}

const USAGE: &str = "usage: window_gallery <tab> <light|dark> <width> <height> <account-state> \
                     <out.png> [--second-factor]\n  \
                     tab: status account security wallet apps cache settings\n  \
                     account-state: unsupported absent locked unopenable needs-password unlocked \
                     unlocked-no-phrase";

/// Report `problem` alongside the usage and stop.
///
/// Nothing is half-written: a gallery that guessed at a mistyped argument would write a file under a
/// name that describes a different picture, which is the one failure a screenshot set cannot survive.
fn refuse(problem: &str) -> ! {
    eprintln!("{problem}\n{USAGE}");
    std::process::exit(2);
}

fn main() {
    let all: Vec<String> = std::env::args().skip(1).collect();
    // Flags are taken out before the positionals are read, so `--second-factor` cannot shift the
    // output path along by one. It did exactly that once, and the picture landed in a file named
    // for the flag -- a gallery is only as trustworthy as the name on each file.
    let args: Vec<&String> = all
        .iter()
        .filter(|argument| !argument.starts_with("--"))
        .collect();
    let Some(tab) = args.first().map(|a| a.as_str()).and_then(tab) else {
        refuse("no tab named");
    };
    let theme = match args.get(1).map(|a| a.as_str()) {
        Some("light") => Theme::Light,
        Some("dark") => Theme::Dark,
        other => refuse(&format!("unknown theme {other:?} — expected light or dark")),
    };
    let (Some(width), Some(height)) = (
        args.get(2).and_then(|value| value.parse().ok()),
        args.get(3).and_then(|value| value.parse().ok()),
    ) else {
        refuse("width and height must both be given, in logical pixels");
    };
    let Some(named) = args.get(4).copied() else {
        refuse("no account state named");
    };
    let Some(account) = account_state(named) else {
        refuse(&format!("unknown account state `{named}`"));
    };
    let Some(path) = args.get(5).copied() else {
        refuse("no output path given");
    };
    // Off by default so the Security pane's no-control second-factor line is what a plain run shows:
    // it is the case the design brief singles out, and the one an invented disabled button would
    // have hidden.
    let second_factor = all.iter().any(|argument| argument == "--second-factor");

    let view = Arc::new(move || view_for(account.clone(), second_factor));
    match photograph_shell(
        theme,
        tab,
        egui::Vec2::new(width, height),
        view,
        std::path::Path::new(path),
    ) {
        Ok((pixels_wide, pixels_high)) => println!("{path} — {pixels_wide} x {pixels_high} px"),
        Err(problem) => {
            eprintln!("{path} was not written: {problem}");
            std::process::exit(1);
        }
    }
}
