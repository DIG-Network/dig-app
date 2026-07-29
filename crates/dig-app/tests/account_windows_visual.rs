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

/// A **manual visual check** of the PASSWORD windows (dig_ecosystem#1817).
///
/// Separate from the phrase walk above because it is the one that has to be screenshotted for the
/// acceptance evidence, and because it is the window a person sees most often — every unlock, every
/// re-auth after an idle lock. Nothing is enrolled and no account is touched: the ceremony collects a
/// password and this test drops it.
///
/// ```text
/// cargo test -p dig-app --test account_windows_visual -- --ignored password --nocapture
/// ```
///
/// Walks both questions in order: the unlock prompt, then the choose-a-password pair a new account is
/// created through.
#[test]
#[ignore = "draws real OS windows for a human to look at; run manually with --ignored"]
fn draw_the_password_windows_for_visual_inspection() {
    use dig_app_core::account::auth::AuthCeremony;
    use dig_app_core::account::passphrase::PasswordCeremony;
    use dig_app_core::account::AccountId;

    let confirmer: std::sync::Arc<dyn dig_app_core::confirm::NativeConfirmer> =
        std::sync::Arc::from(native_confirmer());
    let account = AccountId::new("default");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime for the async ceremony");

    println!("-- drawing the UNLOCK prompt (masked, with a reveal control) --");
    let unlock = PasswordCeremony::to_unlock(std::sync::Arc::clone(&confirmer));
    let collected = runtime.block_on(unlock.collect_unlock_factors(&account, None));
    // Never the password itself — only whether the ceremony completed.
    println!("unlock ceremony completed: {}", collected.is_ok());

    println!("-- drawing the CHOOSE-A-PASSWORD pair (asked twice, 12-character minimum) --");
    let choose = PasswordCeremony::for_a_new_account(confirmer);
    let chosen = runtime.block_on(choose.collect_unlock_factors(&account, None));
    println!("choose ceremony completed: {}", chosen.is_ok());
}
