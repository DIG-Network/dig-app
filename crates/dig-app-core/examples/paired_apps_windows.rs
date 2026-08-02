//! Draw the two paired-app windows with the REAL per-OS confirmer, for visual review.
//!
//! `cargo run -p dig-app-core --example paired_apps_windows -- code|list`
//!
//! An example rather than a test: it deliberately blocks on a window a human has to dismiss, which is
//! the opposite of what a test suite may do. It draws the same [`NativeConfirmer`] the tray draws
//! through, with the same journey functions, so what appears on screen is what a user sees — the point
//! being that a window's spacing, wrapping and clipping can only be judged by looking at it
//! (`professional-ui`'s screenshot rule).

use dig_app_core::confirm::native_confirmer;
use dig_app_core::paired_apps::{manage_paired_apps, offer_pairing_code, PairedApps};
use dig_app_core::pairing::{CapabilitySet, PairedApp, PairingScope};
use dig_app_core::pairing_code::{now_epoch_secs, PairingCode, PairingCodeIssuer};
use std::sync::Mutex;

/// A stand-in for the live pairing surface, holding a fixed cast of apps so the window can be judged
/// against a realistic list rather than an empty one.
struct SampleApps {
    issuer: PairingCodeIssuer,
    apps: Mutex<Vec<PairedApp>>,
}

impl PairedApps for SampleApps {
    fn issue_code(&self, now: u64) -> PairingCode {
        self.issuer.issue(now)
    }
    fn list(&self) -> Vec<PairedApp> {
        self.apps.lock().unwrap().clone()
    }
    fn revoke(&self, pairing_id: &str) -> bool {
        let mut apps = self.apps.lock().unwrap();
        let before = apps.len();
        apps.retain(|a| a.pairing_id != pairing_id);
        apps.len() != before
    }
    fn cancel_code(&self) {
        self.issuer.cancel();
    }
}

fn main() {
    let now = now_epoch_secs();
    let sample = SampleApps {
        issuer: PairingCodeIssuer::new(),
        apps: Mutex::new(vec![
            PairedApp {
                pairing_id: "11111111-1111-1111-1111-111111111111".into(),
                ext_id: "mlibddmbhlgogepnjdienclhnkfpkfah".into(),
                label: Some("DIG for Chrome".into()),
                scope: PairingScope::DigExtension,
                capabilities: CapabilitySet::empty(),
                paired_at: now - 86_400 * 12,
                last_seen_at: Some(now - 300),
            },
            PairedApp {
                pairing_id: "22222222-2222-2222-2222-222222222222".into(),
                ext_id: "com.example.someones-tool".into(),
                label: Some("Someone's Tool".into()),
                scope: PairingScope::ThirdParty,
                capabilities: CapabilitySet::empty(),
                paired_at: now - 7_200,
                last_seen_at: None,
            },
            PairedApp {
                pairing_id: "33333333-3333-3333-3333-333333333333".into(),
                ext_id: "com.example.publisher".into(),
                label: None,
                scope: PairingScope::ThirdParty,
                capabilities: CapabilitySet::empty(),
                paired_at: now - 600,
                last_seen_at: Some(now - 30),
            },
        ]),
    };

    let confirmer = native_confirmer();
    match std::env::args().nth(1).as_deref() {
        Some("list") => {
            println!("{:?}", manage_paired_apps(confirmer.as_ref(), &sample, now));
        }
        _ => {
            println!("{:?}", offer_pairing_code(confirmer.as_ref(), &sample, now));
        }
    }
}
