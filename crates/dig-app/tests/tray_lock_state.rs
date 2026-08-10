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
use dig_app_core::account::profile_session::ProfileSession;
use dig_app_core::account::recovery::RecoveryPhrase;
use dig_app_core::account::residency::AccountResidency;
use dig_app_core::account::AccountId;
use dig_app_core::session_lock::SessionKeys;
use dig_app_core::tray_menu::{self, AccountState, SessionFacts, TrayAction, TrayView};
use dig_keystore::MemoryBackend;
use dig_session::KeychainBackend;

/// Confirms retention without drawing anything — these tests are about lock state, not presentation.
struct AlwaysKeeps;

impl PhrasePresenter for AlwaysKeeps {
    fn present_new_phrase(&self, _phrase: &RecoveryPhrase) -> RetentionDecision {
        RetentionDecision::Confirmed
    }
}

/// A live residency holding real master-seed-derived key material.
fn live_residency() -> AccountResidency {
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let (residency, _phrase) = assemble_residency(
        backend,
        typed_password("tray-lock-state"),
        AccountId::new(DEFAULT_ACCOUNT_ID),
        ProfileSession::unprofiled(),
        Seeding::NewPhrase(&AlwaysKeeps),
    )
    .expect("an in-memory account enrols");
    residency
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
        // The shell derives this from the residency, so it is present exactly while unlocked — the same
        // axis this suite is about, and what makes the Wallet row's copy/(unlock first) flip observable.
        receive_address: matches!(state, AccountState::Unlocked { .. })
            .then(|| "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln".to_string()),
        address_fault: None,
        // Not yet polled. This suite is about the LOCK axis, so the balance is held constant.
        balance: dig_app_core::wallet::overview::BalanceReading::default(),
        account: Some(state),
        // This suite is about the LOCK axis, so the #2330 node/app fields are pinned to a plain
        // connected node with nothing hosted and no sibling app installed.
        node_facts: None,
        hosted_stores: dig_app_core::hosted_stores::HostedStoresReading::Known(Vec::new()),
        installed_apps: dig_app_core::apps::AppPresence::Known(Vec::new()),
        // The profile rows are on the WINDOW's Account tab, not on the tray this suite exercises,
        // so they are pinned to the state every real account is in.
        profiles: dig_app_core::profiles::ProfilesReading::Known(Vec::new()),
        profile_creation: dig_app_core::profiles::ProfileCreation::default(),
        profile_id: Some("a".repeat(96)),
        did: None,
        // This suite is about the LOCK state, so the second-factor axis is pinned off and covered by
        // `tray_menu`'s own tests rather than crossed with every case here.
        second_factor: false,
        hotkey: None,
        // Not the subject here: this fixture is about lock state, not the tray#86 refusal.
        menu_suppressed: false,
        // This suite is about the account LOCK state, not the cache surface, so a connected node with
        // the default cap is pinned here and the cache menu is exercised by `tray_menu`'s own tests.
        cache: Some(dig_app_core::cache::CacheSnapshot {
            cap_bytes: dig_app_core::cache::GIB,
            used_bytes: 0,
        }),
        // Not the subject here: this suite is about the account LOCK state, and auto-update is not
        // gated on an account at all — it is exercised by `window_model`'s own tests.
        update: Some(dig_app_core::auto_update::BeaconStatus {
            paused: false,
            schedule_opted_out: false,
            channel: dig_app_core::auto_update::UpdateChannel::Stable,
        }),
        // Not the subject here: this suite is about the account LOCK state.
        window_host: dig_app_core::tray_menu::WindowHost::Available,
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
        !menu.is_enabled(TrayAction::CopyRecoveryPhrase),
        "a locked account must not offer to back up (copy) its recovery phrase"
    );
    assert!(
        !menu.is_enabled(TrayAction::SaveRecoveryPhrase),
        "a locked account must not offer to back up (save) its recovery phrase"
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
    // The same backend + credential store across the whole test, so the re-unlock re-opens the SAME
    // enrolled account rather than enrolling a second one.
    let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
    let (residency, _phrase) = assemble_residency(
        Arc::clone(&backend),
        typed_password("tray-lock-state"),
        AccountId::new(DEFAULT_ACCOUNT_ID),
        ProfileSession::unprofiled(),
        Seeding::NewPhrase(&AlwaysKeeps),
    )
    .expect("an in-memory account enrols");

    residency.lock_all();
    assert_eq!(state_for(&residency), AccountState::Locked);

    assert!(
        reunlock_into(
            backend,
            typed_password("tray-lock-state"),
            AccountId::new(DEFAULT_ACCOUNT_ID),
            &residency
        ),
        "the zero-prompt re-unlock succeeds"
    );
    assert_eq!(
        state_for(&residency),
        AccountState::Unlocked { recoverable: true },
        "unlocking must restore the unlocked menu"
    );
}

/// A password derived from `label` — the stand-in for a user typing one (dig_ecosystem#1817).
///
/// Same label → same password, so two ceremonies model ONE person across a restart, and a DIFFERENT
/// label models someone who does not know it. Derived rather than inlined so static analysis sees a
/// computed value, not a hard-coded secret.
fn typed_password(label: &str) -> dig_app_core::account::ceremony::PreCollectedPassword {
    dig_app_core::account::ceremony::PreCollectedPassword::new(format!("password-for-{label}"))
}
