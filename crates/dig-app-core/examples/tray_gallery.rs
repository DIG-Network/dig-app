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
    for account in [
        AccountState::Unsupported,
        AccountState::Absent,
        AccountState::Locked,
        AccountState::Unlocked { recoverable: true },
        AccountState::Unlocked { recoverable: false },
    ] {
        // A connected node and a present profile, so the menu is shown at its FULLEST: any row missing here
        // is missing because of the account state, not because the fixture starved it.
        let view = TrayView {
            running: true,
            node_connected: true,
            node: "Node v0.66.0 · 0 capsule(s) cached · 0 store(s) hosted".to_string(),
            account: Some(account.clone()),
            profile_id: Some(
                "b6f1c0a94e2d7c5183ab0f39d84e6c72b1590adf3e7c48d2916b05fa7c3d81e4".into(),
            ),
            did: None,
        };
        let status = tray_menu::status(&view);

        println!("\n═══ account: {account} ═══");
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
