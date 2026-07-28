//! A **manual visual check** of the account windows the user actually sees (dig_ecosystem#1752).
//!
//! The recovery-phrase screens are drawn by the real per-OS confirmer — a topmost, system-modal Win32
//! window on Windows, an `NSAlert` on macOS — which no automated test can inspect. But "the words are
//! legible, numbered, and the warning is readable" is a real acceptance criterion (§6.5: screenshot every
//! view you build), so this test EXISTS to be run by a human with their eyes open:
//!
//! ```text
//! cargo test -p dig-app --test account_windows_visual -- --ignored --nocapture
//! ```
//!
//! It walks the three account windows in order — the display-once phrase screen, the retention
//! confirmation, and the no-recovery-phrase explainer — using a throwaway phrase that is never enrolled
//! anywhere. Dismiss each one; nothing is stored and no account is touched.

#![cfg(any(target_os = "windows", target_os = "macos"))]

use dig_app_core::account::journey::{explain_missing_phrase, WindowedPresenter};
use dig_app_core::account::lifecycle::PhrasePresenter;
use dig_app_core::account::recovery::RecoveryPhrase;
use dig_app_core::confirm::native_confirmer;

#[test]
#[ignore = "draws real OS windows for a human to look at; run manually with --ignored"]
fn draw_every_account_window_for_visual_inspection() {
    let confirmer = native_confirmer();

    // A throwaway phrase: generated here, shown, and dropped. It is never enrolled, so the words on
    // screen belong to no account and are safe to screenshot.
    let throwaway = RecoveryPhrase::generate();
    println!("-- drawing the display-once phrase screen, then the retention confirmation --");
    let decision = WindowedPresenter::new(confirmer.as_ref()).present_new_phrase(&throwaway);
    println!("retention decision: {decision:?}");

    println!("-- drawing the no-recovery-phrase explainer (the legacy-account path) --");
    let acknowledged = explain_missing_phrase(confirmer.as_ref());
    println!("explainer acknowledged: {acknowledged:?}");
}
