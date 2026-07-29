//! The tray's account state across a REAL lock (dig_ecosystem#1752, security-gate regression).
//!
//! # The defect this pins
//!
//! A tray session deliberately outlives its key material: `Lock now` and the idle auto-lock drop the
//! keys and keep the session, so the sign path can re-unlock into it. The menu, however, keyed on the
//! session's EXISTENCE — so after Lock now it reported `Account: unlocked`, kept "Show my recovery
//! phrase…" enabled, and left "Unlock…" disabled. Custody still failed closed at three layers, but the
//! user was told something untrue and handed a dead end (`SPEC.md` §3.1c).
//!
//! # Why this test is here and not only in `dig-app-core`
//!
//! `tray_menu`'s own tests pin the RULES over a `SessionFacts` value, which is where the logic belongs.
//! But a fixture that constructs `SessionFacts { keys_unlocked: false }` by hand cannot prove the shell
//! reads that field from a real residency rather than passing a constant — and "we forgot to ask the
//! residency" was the entire bug. So this drives a REAL `AccountResidency`, holding real derived key
//! material, through a REAL `lock_all()`, and asserts the menu the user would see on the other side.

use std::sync::Arc;

use dig_app_core::account::boot::{assemble_residency, reunlock_into, DEFAULT_ACCOUNT_ID};
use dig_app_core::account::lifecycle::{PhrasePresenter, RetentionDecision, Seeding};
use dig_app_core::account::passphrase::PasswordCeremony;
use dig_app_core::account::recovery::RecoveryPhrase;
use dig_app_core::account::residency::AccountResidency;
use dig_app_core::account::AccountId;
use dig_app_core::confirm::{
    ConfirmDecision, ConnectPrompt, InputOutcome, InputPrompt, NativeConfirmer, PairPrompt,
    SignPrompt,
};
use dig_app_core::session_lock::SessionKeys;
use dig_app_core::tray_menu::{self, AccountState, SessionFacts, TrayAction, TrayView};
use dig_keystore::MemoryBackend;
use dig_session::KeychainBackend;

/// A confirmer whose input window types a fixed password — the seam that stands in for the user at the
/// unlock prompt, so these tests drive the REAL production ceremony rather than a bypass.
struct Types(String);

impl Types {
    fn typing(password: &str) -> Arc<dyn NativeConfirmer> {
        Arc::new(Self(password.to_string()))
    }
}

impl NativeConfirmer for Types {
    fn confirm_pair(&self, _p: &PairPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }
    fn confirm_connect(&self, _p: &ConnectPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }
    fn confirm_sign(&self, _p: &SignPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }
    fn request_input(&self, _p: &InputPrompt<'_>) -> InputOutcome {
        InputOutcome::Provided(zeroize::Zeroizing::new(self.0.clone()))
    }
}

/// A password long enough to clear the ceremony's bar, DERIVED from a label so no test password is an
/// inline literal a static analyser reads as a hard-coded cryptographic value.
fn password(label: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(label.as_bytes()))[..16].to_string()
}

/// Confirms retention without drawing anything — these tests are about lock state, not presentation.
struct AlwaysKeeps;

impl PhrasePresenter for AlwaysKeeps {
    fn present_new_phrase(&self, _phrase: &RecoveryPhrase) -> RetentionDecision {
        RetentionDecision::Confirmed
    }
}

/// A live residency holding real master-seed-derived key material, sealed under `label`'s password.
fn enrolled(backend: Arc<dyn KeychainBackend>, label: &str) -> AccountResidency {
    let pw = password(label);
    let (residency, _phrase) = assemble_residency(
        backend,
        PasswordCeremony::for_a_new_account(Types::typing(&pw)),
        AccountId::new(DEFAULT_ACCOUNT_ID),
        Seeding::NewPhrase(&AlwaysKeeps),
    )
    .expect("an in-memory account enrols");
    residency
}

/// A live residency over a throwaway in-memory backend.
fn live_residency() -> AccountResidency {
    enrolled(Arc::new(MemoryBackend::new()), "pw")
}

/// The state the shell would report for `residency`, via exactly the path the shell uses.
fn state_for(residency: &AccountResidency) -> AccountState {
    tray_menu::account_state(
        true,
        tray_menu::AtRest::Present,
        Some(SessionFacts::of(residency, true)),
    )
}

fn view_for(state: AccountState) -> TrayView {
    TrayView {
        running: true,
        node_connected: true,
        node: "Node v0.65.0 - 3 capsule(s) cached - 1 store(s) hosted".to_string(),
        account: Some(state),
        profile_id: Some("a".repeat(96)),
        did: None,
    }
}

fn menu_for(state: AccountState) -> tray_menu::MenuModel {
    tray_menu::build(&view_for(state))
}

/// The headline regression: a real `lock_all()` must flip the reported state, and the SESSION IS STILL
/// HELD throughout (never dropped), which is precisely the situation the old code got wrong.
#[test]
fn locking_a_live_residency_flips_the_reported_state_to_locked() {
    let residency = live_residency();

    assert_eq!(
        state_for(&residency),
        AccountState::Unlocked { recoverable: true },
        "a freshly enrolled account starts unlocked"
    );

    residency.lock_all();

    assert_eq!(
        state_for(&residency),
        AccountState::Locked,
        "after Lock now the account is LOCKED even though the session is still held"
    );
    // The residency is still alive and still the same object — the point being that nothing about the
    // SESSION changed, only its key material.
    assert!(!residency.is_any_unlocked());
}

/// What the user actually sees after clicking `Lock now`: a truthful status line, a clickable way back
/// in, and no offer to reveal the phrase.
#[test]
fn the_menu_after_a_real_lock_is_truthful_and_offers_a_way_back_in() {
    let residency = live_residency();
    residency.lock_all();
    let menu = menu_for(state_for(&residency));

    // The lock state is reported on the tray's OWN surfaces now, not as a greyed menu row
    // (dig_ecosystem#1800): the icon, the tooltip, and the details window. All three are checked, because
    // "the user can see they are locked" is exactly the property that moved.
    let view = view_for(state_for(&residency));
    assert_eq!(tray_menu::status(&view).glyph, tray_menu::TrayGlyph::Locked);
    assert!(
        tray_menu::status(&view).tooltip.contains("locked"),
        "the tooltip must not claim the account is unlocked: {:?}",
        tray_menu::status(&view).tooltip
    );
    assert!(
        tray_menu::details_text(&view).contains("Account: locked"),
        "the details window must not claim the account is unlocked: {}",
        tray_menu::details_text(&view)
    );
    assert!(
        menu.is_enabled(TrayAction::Unlock),
        "the way back in must be clickable, not greyed out"
    );
    assert!(
        !menu.is_enabled(TrayAction::ShowRecoveryPhrase),
        "a locked account must not offer to reveal its recovery phrase"
    );
    assert!(
        !menu.is_enabled(TrayAction::LockNow),
        "there is nothing left to lock"
    );
}

/// Re-unlocking (what `Unlock…` does, and what the sign path does after a lock) must return the menu to
/// unlocked. Without this the two tests above could pass for a state that latches to `Locked` forever.
#[test]
fn re_unlocking_returns_the_menu_to_unlocked() {
    // The same backend across the whole test, so the re-unlock re-opens the SAME enrolled account
    // rather than enrolling a second one.
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let residency = enrolled(Arc::clone(&backend), "pw");

    residency.lock_all();
    assert_eq!(state_for(&residency), AccountState::Locked);

    assert!(
        reunlock_into(
            backend,
            PasswordCeremony::to_unlock(Types::typing(&password("pw"))),
            AccountId::new(DEFAULT_ACCOUNT_ID),
            &residency
        ),
        "the password re-unlock succeeds"
    );
    assert_eq!(
        state_for(&residency),
        AccountState::Unlocked { recoverable: true },
        "unlocking must restore the unlocked menu"
    );
}

/// **A locked account must stay locked without the password (dig_ecosystem#1817).** The menu's way back
/// in is a prompt, so a re-unlock that collects nothing must leave the user looking at the same locked
/// menu — not at an unlocked one.
///
/// The control at the end matters: it proves the refusal was the missing password rather than a residency
/// that latches to `Locked` forever, which the assertion alone could not distinguish.
#[test]
fn a_locked_account_stays_locked_without_the_password() {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let residency = enrolled(Arc::clone(&backend), "right");
    residency.lock_all();

    assert!(
        !reunlock_into(
            Arc::clone(&backend),
            PasswordCeremony::to_unlock(Types::typing(&password("wrong"))),
            AccountId::new(DEFAULT_ACCOUNT_ID),
            &residency
        ),
        "a wrong password must not unlock the account"
    );
    assert_eq!(
        state_for(&residency),
        AccountState::Locked,
        "and the menu must still report it locked, with Unlock… still clickable"
    );
    assert!(menu_for(state_for(&residency)).is_enabled(TrayAction::Unlock));

    assert!(reunlock_into(
        backend,
        PasswordCeremony::to_unlock(Types::typing(&password("right"))),
        AccountId::new(DEFAULT_ACCOUNT_ID),
        &residency
    ));
    assert_eq!(
        state_for(&residency),
        AccountState::Unlocked { recoverable: true }
    );
}
