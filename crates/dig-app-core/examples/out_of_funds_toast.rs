//! Raise the real out-of-funds notification, so a person can watch it appear (dig-app#289).
//!
//! This is the §2.6 evidence hook for the notification half of #289: it drives the SAME
//! [`Shortfall`] the agent uses, through the SAME [`native_notifier`], so what appears on screen is
//! what a genuinely-short wallet produces — not a hand-written toast that merely looks like one.
//!
//! ```text
//! cargo run -p dig-app-core --example out_of_funds_toast -- dig
//! cargo run -p dig-app-core --example out_of_funds_toast -- xch
//! cargo run -p dig-app-core --example out_of_funds_toast -- stuck
//! ```
//!
//! `stuck` is the one worth looking at: a wallet with no XCH cannot pay the fee that RELEASES
//! collateral, so the $DIG already locked has no way back. It is the worst state in the system and
//! it is worded differently from the other two on purpose.
//!
//! # What it does not prove
//!
//! **The click.** On Windows the toast carries a `dig-app:deposit` protocol activation, which
//! completes only where that scheme is registered — dig-installer's job, and not done yet. On macOS
//! and Linux the current backends (`osascript` and `notify-send` as subprocesses) cannot deliver a
//! click at all. The notification stands alone on every host, which is why none of its copy mentions
//! clicking.

use dig_app_core::activity::funding::{FundingFacts, Shortfall, StoreCoinState};
use dig_app_core::notify::native_notifier;

fn main() {
    let which = std::env::args().nth(1).unwrap_or_else(|| "dig".to_string());

    // A node maintaining three stores. The unsynced one is present in every case deliberately: it is
    // the store that must NOT be counted, and seeing the figure come out as one rather than two is
    // the whole point of watching this by hand.
    let stores = vec![
        StoreCoinState::WantsCollateral,
        StoreCoinState::WithheldUnsynced,
        StoreCoinState::Collateralised,
    ];

    let facts = match which.as_str() {
        "xch" => FundingFacts {
            dig_base_units: 1_000_000,
            xch_mojos: 0,
            dig_per_store: 20_000,
            fee_mojos: 1_000_000,
            stores,
        },
        "stuck" => FundingFacts {
            dig_base_units: 1_000_000,
            xch_mojos: 0,
            dig_per_store: 20_000,
            fee_mojos: 1_000_000,
            stores: vec![
                StoreCoinState::WantsReclaim,
                StoreCoinState::WithheldUnsynced,
            ],
        },
        _ => FundingFacts {
            dig_base_units: 0,
            xch_mojos: 1_000_000_000_000,
            dig_per_store: 20_000,
            fee_mojos: 1_000_000,
            stores,
        },
    };

    let shortfall = Shortfall::of(&facts);
    match shortfall.notification() {
        Some(toast) => {
            println!("shortfall: {shortfall:?}");
            println!("title: {}", toast.title);
            println!("body:  {}", toast.body);
            println!(
                "route: {:?} (best-effort; see the module docs for which hosts deliver it)",
                toast.route
            );
            native_notifier().show(&toast);
            println!("shown — look at your notification area");
        }
        None => println!("this wallet is not short of anything; nothing is shown"),
    }
}
