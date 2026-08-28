//! Watch the activity gate hold a notification and then release it (dig-app#312).
//!
//! This is the §2.6 evidence for the gate: a person on a real machine, watching a real toast arrive
//! when they touch the keyboard and not before. It uses the SHIPPING pieces — the real
//! [`presence`] probe (`GetLastInputInfo` on Windows, `ioreg` on macOS) and the real
//! [`native_notifier`] backend — so what appears on screen is what the app will draw.
//!
//! ```text
//! cargo run --example activity_gate -- [away_after_secs]
//! ```
//!
//! `away_after_secs` defaults to 10 rather than the shipped five minutes, so the hold and the
//! release can both be observed inside one sitting. Nothing else is substituted.
//!
//! THREE conditions are held, with detection times backdated to different points in the past, so
//! one run demonstrates every property at once: the release arrives ONCE, it names the entries that
//! are still fresh, each carries its OWN age — and the third, backdated past the 12-hour bound, is
//! DROPPED rather than delivered late, so it never appears at all.

use std::time::{Duration, Instant};

use dig_app_core::notify::gate::{ActivityGate, HoldKey, HoldPolicy};
use dig_app_core::notify::presence::{presence_from_idle, system_idle, Presence};
use dig_app_core::notify::{native_notifier, Notification, Route};

fn main() {
    let away_after = Duration::from_secs(
        std::env::args()
            .nth(1)
            .and_then(|a| a.parse().ok())
            .unwrap_or(10),
    );

    let now = Instant::now();
    let mut gate = ActivityGate::new(HoldPolicy {
        max_hold: Duration::from_secs(12 * 3600),
        repeat_after: Duration::from_secs(3600),
    });

    // Backdated so the released copy has real ages to report — this is what an overnight hold looks
    // like on the morning it is released.
    let six_hours_ago = now - Duration::from_secs(6 * 3600);
    let three_hours_ago = now - Duration::from_secs(3 * 3600);
    // Past `max_hold`. A person running this must SEE that it does not arrive: a two-day-old notice
    // is not worth an interruption in the form it was written, and delivering it on the next mouse
    // move would be the 03:00 toast wearing a different hat.
    let fifty_hours_ago = now - Duration::from_secs(50 * 3600);
    gate.hold(
        six_hours_ago,
        HoldKey::Installed,
        Notification {
            title: "dig-app updated to 13.15.0".into(),
            body: "A new version was installed.".into(),
            route: None,
        },
    );
    gate.hold(
        three_hours_ago,
        HoldKey::Collateral,
        Notification {
            title: "Add $DIG — your stores are uncollateralised".into(),
            body: "Add 24 $DIG to cover 12 stores for epoch 7.".into(),
            route: Some(Route::Deposit),
        },
    );

    gate.hold(
        fifty_hours_ago,
        HoldKey::OutOfFunds,
        Notification {
            title: "A collateral spend was skipped".into(),
            body: "This one is 50 hours old and MUST NOT appear: it is past the 12-hour bound."
                .into(),
            route: Some(Route::Deposit),
        },
    );

    println!("three conditions held; the 50-hour-old one is past the bound and must NOT appear.");
    println!("away after {away_after:?}.");
    println!("stop touching the machine — nothing should appear. then move the mouse.\n");

    loop {
        let idle = system_idle();
        let presence = presence_from_idle(idle, away_after);
        println!(
            "idle {:>6} | {presence:?}",
            idle.map_or("?".to_string(), |d| format!("{}s", d.as_secs()))
        );

        if let Some(toast) = gate.poll(Instant::now(), presence) {
            println!("\nRELEASED:\n  {}\n  {}", toast.title, toast.body);
            native_notifier().show(&toast);
            return;
        }
        if presence == Presence::Unobservable {
            println!(
                "\nthis host cannot observe input; the gate will hold until the entries expire."
            );
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
