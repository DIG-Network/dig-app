//! Print the tray menu, icon and tooltip for every account state, so a human can READ the whole surface
//! without clicking through five installs (dig_ecosystem#1800).
//!
//! # Why this exists
//!
//! The defect this rewrite fixes — five greyed status rows, and Set-up/Restore enabled only when no account
//! exists — was invisible from the code and obvious the moment someone looked at the menu on a machine that
//! HAD an account. Native menus cannot be constructed inside a `cargo test` process on this stack
//! (`STATUS_ACCESS_VIOLATION` from `muda`, intermittently, even from a `harness = false` main thread), so
//! there is nowhere in the test suite a whole-menu render could live.
//!
//! This is the next best thing and it is cheap: the MODEL is what every rule lives in, and printing it for
//! all five states puts the entire surface — every row, its enabled state, its nesting, the icon and the
//! tooltip — in front of a reviewer at once.
//!
//! ```text
//! cargo run -p dig-app-core --example tray_gallery
//! ```

use dig_app_core::tray_menu::{self, AccountState, MenuRow, TrayView};

fn main() {
    // Both halves of the second-factor axis, because the Security submenu's row depends on it: a gallery
    // that rendered only one would stop showing half the menu the moment two-factor shipped.
    // ALL SIX user-visible account states (SPEC §3.1c), not the five that happen to be common. The two
    // added late — an account with no password yet, and one that will not open — are precisely the ones
    // whose rows name a DIFFERENT remedy from `Locked`, so a gallery without them cannot show the
    // difference a reviewer is here to check (dig_ecosystem#1841).
    let states = [
        AccountState::Unsupported,
        AccountState::Absent,
        AccountState::NeedsPassword,
        AccountState::Locked,
        AccountState::Unopenable,
        AccountState::Unlocked { recoverable: true },
        AccountState::Unlocked { recoverable: false },
    ];
    for (account, second_factor) in states
        .iter()
        .flat_map(|account| [false, true].map(|enrolled| (account.clone(), enrolled)))
    {
        // A connected node and a present profile, so the menu is shown at its FULLEST: any row missing here
        // is missing because of the account state, not because the fixture starved it.
        let view = TrayView {
            running: true,
            node_connected: true,
            node: "Node v0.66.0 · 0 capsule(s) cached · 0 store(s) hosted".to_string(),
            // A real reading, so the gallery photographs the Wallet row as a funded account sees it.
            balance: dig_app_core::wallet::overview::BalanceReading::Known(
                dig_app_core::wallet::overview::Balances {
                    xch_mojos: 1_250_000_000_000,
                    dig_units: 3_400,
                },
            ),
            account: Some(account.clone()),
            // A connected node, matching the `node` line above: the gallery photographs the
            // account states, so the #2330 fields are pinned rather than varied.
            node_facts: None,
            hosted_stores: dig_app_core::hosted_stores::HostedStoresReading::Known(Vec::new()),
            installed_apps: dig_app_core::apps::AppPresence::Known(Vec::new()),
            // The profile rows live in the WINDOW, not on the tray, so this gallery pins them to
            // the state every real account is in rather than varying them.
            profiles: dig_app_core::profiles::ProfilesReading::Known(Vec::new()),
            profile_creation: dig_app_core::profiles::ProfileCreation::NoChainTransport,
            // Present exactly while unlocked, as the shell's live derivation off the residency is.
            receive_address: matches!(account, AccountState::Unlocked { .. }).then(|| {
                "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln".to_string()
            }),
            address_derivation_failed: false,
            profile_id: Some(
                "b6f1c0a94e2d7c5183ab0f39d84e6c72b1590adf3e7c48d2916b05fa7c3d81e4".into(),
            ),
            did: None,
            second_factor,
            // The gallery photographs the account states; the shortcut is live in the real shell and its
            // own row label is asserted in `tray_menu`'s tests.
            hotkey: Some(dig_app_core::hotkey::HotkeyState::Registered(
                dig_app_core::hotkey::Hotkey::default(),
            )),
            // A beacon that answered — running, on stable, with its daily schedule intact — so the
            // gallery shows the populated Auto-update submenu rather than the "could not be asked" row.
            update: Some(dig_app_core::auto_update::BeaconStatus {
                paused: false,
                schedule_opted_out: false,
                channel: dig_app_core::auto_update::UpdateChannel::Stable,
            }),
            // A connected node reporting a default 1 GiB cap with a little in use, so the gallery shows
            // the populated Cache submenu.
            cache: Some(dig_app_core::cache::CacheSnapshot {
                cap_bytes: dig_app_core::cache::GIB,
                used_bytes: 350 * dig_app_core::cache::MIB,
            }),
            // The gallery photographs the ordinary states; the refused-menu tooltip is asserted in
            // `tray_menu`'s tests rather than shot here (dig-app#86).
            menu_suppressed: false,
            // The gallery is about account states, not the window-host fallback.
            window_host: dig_app_core::tray_menu::WindowHost::Available,
        };
        let status = tray_menu::status(&view);

        println!("\n═══ account: {account} · two-factor: {second_factor} ═══");
        println!("icon    : {:?}", status.glyph);
        println!("tooltip : {}", status.tooltip.replace('\n', " ⏎ "));
        println!("menu    :");
        print_rows(&tray_menu::build(&view).rows, 0);
        println!("details window:");
        for line in tray_menu::details_text(&view).lines() {
            println!("    │ {line}");
        }
    }
}

/// Print `rows` at `depth`, marking each action as enabled or greyed.
///
/// The enabled marker is `[x]`/`[ ]` rather than words because the point of reading this output is scanning
/// a column for greyed rows — the defect being fixed was five of them in a row.
fn print_rows(rows: &[MenuRow], depth: usize) {
    let pad = "  ".repeat(depth + 2);
    for row in rows {
        match row {
            MenuRow::Separator => println!("{pad}  ───────────────"),
            MenuRow::Action { label, enabled, .. } => {
                println!("{pad}[{}] {label}", if *enabled { "x" } else { " " })
            }
            MenuRow::Submenu { label, rows } => {
                println!("{pad}[>] {label}");
                print_rows(rows, depth + 1);
            }
        }
    }
}
