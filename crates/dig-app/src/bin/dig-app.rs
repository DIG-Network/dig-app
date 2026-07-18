//! `dig-app` — the branded per-user identity-agent shell.
//!
//! This binary is the process edge: it resolves the real host [`AppEnvironment`] (env vars, display
//! presence), builds the [`Agent`] core over it, and then either mounts the desktop **tray shell**
//! (Windows system tray · macOS menu-bar · Linux AppIndicator) over the agent when a display is
//! present, or **degrades to running the headless agent** on a GUI-less host. All real logic lives
//! in [`dig_app_core`] (and is unit-tested there); this shell stays deliberately thin.
//!
//! The tray is the crate's default `tray` feature. It degrades headless in two ways: the pure
//! form-factor decision ([`FormFactor::detect`] via [`AppEnvironment::form_factor`]) skips the tray
//! when no display is detected, and — belt and braces — a tray that fails to initialize on a
//! display-present host falls back to the headless agent rather than aborting.
//!
//! The engine connection is the U3 stub ([`NullConnector`]): the agent surfaces "engine not yet
//! reachable" until U6 stands up the identity-authenticated session listener. Keys/profiles/wallet
//! (U4/U5) and the `dign` gateway (U7) remain stubs.

use dig_app_core::agent::Agent;
use dig_app_core::confirm::native_confirmer;
use dig_app_core::engine::NullConnector;
use dig_app_core::environment::AppEnvironment;
use dig_app_core::form_factor::FormFactor;
use dig_app_core::loopback::SignReauthGate;
use dig_app_core::profiles::{
    did_hash, IdentityStore, KeystoreSealer, ProfileManager, RootUnlock, UnlockedIdentities,
};
use dig_app_core::session_lock::{
    panic_safe_lock_callback, PlatformScreenLockSource, ScreenLockGuard, ScreenLockSource,
    SessionLock, SystemClock, DEFAULT_IDLE_TIMEOUT,
};
use dig_app_core::sign_service::{SessionReauthGate, TraySessionLock};
use dig_app_core::{sign_service, storage, Os};
use std::sync::Arc;

/// The live session-lock wiring the tray drives once the APP-SIGN channel is up: the shared
/// [`SessionLock`] (lock-now / idle poll / OS screen-lock all act on it, and the sign path
/// re-authenticates through it) plus the OS screen-lock subscription guard, kept alive for as long as
/// the tray runs.
struct TraySession {
    lock: TraySessionLock,
    _screen_guard: Box<dyn ScreenLockGuard>,
}

fn main() {
    // Install the shared logging stack FIRST, before anything else can emit an event that would
    // otherwise be silently dropped. Held for the whole process lifetime; see `logging`'s docs for
    // why a plain local guard is enough here (this is the crate's one entrypoint).
    let _log_guard = dig_app::logging::init();

    let version = env!("CARGO_PKG_VERSION");
    let env = resolve_environment();
    tracing::info!(version, os = ?env.os, has_display = env.has_display, "dig-app starting");

    let agent = match Agent::from_env(&env, NullConnector) {
        Ok(agent) => agent,
        Err(e) => {
            tracing::error!(error = %e, "dig-app cannot start");
            eprintln!("dig-app {version}: cannot start — {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(endpoint = %agent.endpoint(), "engine endpoint resolved");
    eprintln!(
        "dig-app {version} — user identity agent starting (endpoint: {})",
        agent.endpoint()
    );

    match env.form_factor() {
        FormFactor::Tray => {
            // A desktop session is present, so the terminal native-confirm gate is available — bring
            // the APP-SIGN extension↔dig-app signing channel live (best-effort; see the fn's docs).
            // A live channel hands back the session-lock the tray drives (lock-now / idle / OS lock).
            let tray_session = start_sign_service(&env);
            run_tray_or_headless(agent, tray_session)
        }
        FormFactor::Headless => {
            tracing::info!("no desktop display — running as headless agent (no tray)");
            eprintln!("dig-app: no desktop display — running as headless agent (no tray)");
            agent.run();
        }
    }
}

/// Mount the tray shell, degrading to the headless agent if the tray cannot be built (no display,
/// no desktop stack) or if the `tray` feature is disabled at build time.
fn run_tray_or_headless(agent: Agent<NullConnector>, session: Option<TraySession>) {
    #[cfg(feature = "tray")]
    match tray::run(agent, session) {
        // The event loop owns the process once mounted, so this arm is unreachable in practice.
        Ok(()) => {}
        // `run` returns only on the degrade path, handing the agent back so we can serve headless.
        Err((reason, agent)) => {
            eprintln!("dig-app: tray unavailable ({reason}) — running as headless agent");
            agent.run();
        }
    }
    #[cfg(not(feature = "tray"))]
    {
        let _ = session;
        eprintln!("dig-app: built without the tray feature — running as headless agent");
        agent.run();
    }
}

/// Bring the APP-SIGN loopback signing channel live on boot (dig_ecosystem#958, `SPEC.md` §5.6).
///
/// The signing channel needs TWO things a headless / locked host cannot provide, so this is
/// deliberately best-effort and fail-closed — it starts the server only when both hold, and simply
/// logs + returns otherwise (never blocks or crashes the shell):
///
/// 1. **An unlocked active profile** — the signer + the sealed-store DEK resolve the identity from
///    the unlocked session. Only Windows/macOS can unlock zero-prompt via the OS credential store;
///    Linux needs a user passphrase (a UX not yet wired), so the channel defers there.
/// 2. **A desktop session** — guaranteed here because this runs only on the [`FormFactor::Tray`] path,
///    so the per-OS [`native_confirmer`] can raise a real biometric confirm.
///
/// When both hold it assembles the [`FrameRouter`](dig_app_core::loopback::FrameRouter) over the
/// active profile, wires the session-lock (WSEC-D, dig_ecosystem#967) so the sign path re-authenticates
/// after a lock, restores any persisted pairings/whitelist/nonce ledger, serves the two loopback
/// listeners on a background thread (the OS event loop keeps the main thread), and hands the tray the
/// [`TraySession`] it drives (lock-now / idle poll / OS screen-lock). Returns `None` on any deferral.
fn start_sign_service(env: &AppEnvironment) -> Option<TraySession> {
    // Zero-prompt unlock is only available where the OS credential store is the custody primary.
    if !matches!(env.os, Os::Windows | Os::MacOs) {
        tracing::info!("APP-SIGN loopback deferred: no zero-prompt profile unlock on this OS yet");
        return None;
    }
    let brand_dir = match env.brand_dir() {
        Ok(dir) => dir,
        Err(e) => {
            tracing::warn!(error = %e, "APP-SIGN loopback not started: could not resolve the AppData directory");
            return None;
        }
    };

    // Unlock the user's profiles via the OS credential store, then pick the active one.
    let session = UnlockedIdentities::new();
    if let Err(e) = unlock_profiles(&brand_dir, &session) {
        tracing::warn!(error = %e, "APP-SIGN loopback not started: profile unlock failed");
        return None;
    }
    let manager = profile_manager(&brand_dir, &session);
    let Ok(Some(active_did)) = manager.active_did() else {
        tracing::info!("APP-SIGN loopback not started: no active profile yet");
        return None;
    };

    // The session-lock the tray drives and the sign path re-authenticates through — the SAME shared
    // controller over the SAME unlocked session, so a lock the tray triggers is the lock the signer sees.
    let lock: TraySessionLock = Arc::new(SessionLock::new(
        session.clone(),
        SystemClock::new(),
        DEFAULT_IDLE_TIMEOUT,
    ));

    let profile_dir = storage::profile_dir(&brand_dir, &did_hash(&active_did));
    let confirmer: Arc<dyn dig_app_core::confirm::NativeConfirmer> = Arc::from(native_confirmer());
    let reauth_gate = build_reauth_gate(
        Arc::clone(&lock),
        brand_dir.clone(),
        session.clone(),
        active_did.clone(),
    );
    let router = sign_service::build_router(session, &active_did, &profile_dir, confirmer)
        .with_reauth_gate(reauth_gate);

    // Subscribe to OS screen-lock events, containing any callback panic before it can cross the
    // extern-"system" FFI boundary (WSEC-D adversarial hardening). The returned guard lives in the
    // TraySession so the subscription stays alive for the whole tray lifetime.
    let lock_for_screen = Arc::clone(&lock);
    let screen_guard = PlatformScreenLockSource::new().start(panic_safe_lock_callback(move || {
        lock_for_screen.on_screen_locked();
    }));

    std::thread::Builder::new()
        .name("dig-app-sign".to_string())
        .spawn(move || {
            if let Err(e) = sign_service::serve_blocking(router) {
                tracing::error!(error = %e, "APP-SIGN loopback server exited");
            }
        })
        .map(|_| tracing::info!("APP-SIGN loopback signing channel started on port 9779"))
        .unwrap_or_else(|e| tracing::error!(error = %e, "could not spawn the APP-SIGN thread"));

    Some(TraySession {
        lock,
        _screen_guard: screen_guard,
    })
}

/// The production sign-path re-auth gate: on a sign after a lock it re-unlocks ONLY the signing
/// profile (`active_did`) from the OS credential store (the keystore's job) before the signature
/// proceeds — never every profile's DEK, since only the active profile signs (dig_ecosystem#973).
/// Re-derives a fresh [`ProfileManager`] per re-unlock so nothing but the shared session outlives
/// this call.
fn build_reauth_gate(
    lock: TraySessionLock,
    brand_dir: std::path::PathBuf,
    session: UnlockedIdentities,
    active_did: String,
) -> Arc<dyn SignReauthGate> {
    Arc::new(SessionReauthGate::new(lock, move || {
        reunlock_signing_profile(&brand_dir, &session, &active_did).is_ok()
    }))
}

/// Re-unlock JUST the signing profile's identity into `session` from the OS credential store (the
/// zero-prompt custody primary on Windows/macOS), leaving every other profile locked.
fn reunlock_signing_profile(
    brand_dir: &std::path::Path,
    session: &UnlockedIdentities,
    did: &str,
) -> Result<(), dig_app_core::profiles::ProfileError> {
    profile_manager(brand_dir, session).unlock_profile(did, RootUnlock::OsKeychain)
}

/// Re-unlock every profile's identity into `session` from the OS credential store — the BOOT-time
/// re-unlock (a restarted app must reopen ALL of its profiles), distinct from the sign-path re-auth
/// which re-unlocks only the signing profile ([`reunlock_signing_profile`]).
fn unlock_profiles(
    brand_dir: &std::path::Path,
    session: &UnlockedIdentities,
) -> Result<(), dig_app_core::profiles::ProfileError> {
    profile_manager(brand_dir, session)
        .unlock_all(RootUnlock::OsKeychain)
        .map(|_count| ())
}

/// A [`ProfileManager`] over `session`, rooted at `brand_dir`, with the production identity store.
fn profile_manager(
    brand_dir: &std::path::Path,
    session: &UnlockedIdentities,
) -> ProfileManager<KeystoreSealer> {
    ProfileManager::new(
        brand_dir.to_path_buf(),
        KeystoreSealer::new(session.clone()),
        IdentityStore::production(session.clone()),
    )
}

/// Resolve the real per-user host facts the agent boots from. This is the impure process edge; the
/// pure derivations happen in [`AppEnvironment`].
fn resolve_environment() -> AppEnvironment {
    let os = current_os();
    AppEnvironment {
        os,
        app_data_root: app_data_root(os),
        user: current_user(),
        runtime_dir: std::env::var("XDG_RUNTIME_DIR").unwrap_or_default(),
        has_display: has_display(os),
    }
}

/// The OS this build is running on, mapped onto the core's [`Os`]. Unknown targets are treated as
/// Linux (the Unix-socket + XDG conventions).
fn current_os() -> Os {
    if cfg!(target_os = "windows") {
        Os::Windows
    } else if cfg!(target_os = "macos") {
        Os::MacOs
    } else {
        Os::Linux
    }
}

/// The per-OS AppData root env var: `%LOCALAPPDATA%` (Windows), `$HOME` (macOS), `$XDG_DATA_HOME`
/// (Linux, falling back to `$HOME/.local/share` per the XDG default).
fn app_data_root(os: Os) -> String {
    match os {
        Os::Windows => std::env::var("LOCALAPPDATA").unwrap_or_default(),
        Os::MacOs => std::env::var("HOME").unwrap_or_default(),
        Os::Linux => std::env::var("XDG_DATA_HOME").unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| format!("{h}/.local/share"))
                .unwrap_or_default()
        }),
    }
}

/// The current login user, used to namespace the per-user IPC endpoint.
fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_string())
}

/// Whether a usable desktop display is present. On Linux this is a real check (`$DISPLAY` /
/// `$WAYLAND_DISPLAY`); on Windows/macOS an interactive desktop is assumed, and a tray that still
/// cannot mount degrades at runtime via [`run_tray_or_headless`].
fn has_display(os: Os) -> bool {
    match os {
        Os::Linux => {
            !std::env::var("DISPLAY").unwrap_or_default().is_empty()
                || !std::env::var("WAYLAND_DISPLAY")
                    .unwrap_or_default()
                    .is_empty()
        }
        Os::Windows | Os::MacOs => true,
    }
}

/// The desktop tray / menu-bar shell. Compiled only with the default `tray` feature; a headless
/// build omits it entirely.
#[cfg(feature = "tray")]
mod tray {
    use super::TraySession;
    use dig_app_core::agent::{Agent, SharedStatus};
    use dig_app_core::engine::{EngineState, NullConnector};
    use std::time::{Duration, Instant};
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIconBuilder};

    /// How long to let the agent thread flush + stop after "Quit" before the loop exits the process.
    const GRACEFUL_STOP: Duration = Duration::from_secs(1);
    /// How often the tray repaints its status labels from the shared agent status.
    const REFRESH: Duration = Duration::from_millis(500);

    /// Mount the tray over `agent` and run the platform event loop. The tray is built FIRST (that is
    /// what fails on a display-less host); only once it mounts do we spawn the agent's blocking run
    /// loop on a background thread, leaving the OS event loop on the main thread (required on macOS).
    ///
    /// On success the event loop owns the process for its lifetime and this never returns. On
    /// failure it hands `agent` back in the `Err` so the caller can still run it headless.
    #[allow(clippy::result_large_err)]
    pub fn run(
        agent: Agent<NullConnector>,
        session: Option<TraySession>,
    ) -> Result<(), (String, Agent<NullConnector>)> {
        let event_loop = EventLoopBuilder::new().build();

        let menu = Menu::new();
        let running_item = MenuItem::new("DIG — starting…", false, None);
        let engine_item = MenuItem::new("Engine: connecting…", false, None);
        let profile_item = MenuItem::new("Profile: (none)", false, None);
        // "Lock now" one-tap re-seals the session (§WSEC-D); it is enabled only when a live unlocked
        // session exists to lock — otherwise there is nothing to drop, so it stays disabled.
        let lock_item = MenuItem::new("Lock now", session.is_some(), None);
        let quit_item = MenuItem::new("Quit DIG", true, None);
        if let Err(e) = menu.append_items(&[
            &running_item,
            &engine_item,
            &profile_item,
            &PredefinedMenuItem::separator(),
            &lock_item,
            &quit_item,
        ]) {
            return Err((format!("menu build failed: {e}"), agent));
        }

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("DIG — user identity agent")
            .with_icon(brand_icon())
            .build();
        let _tray = match tray_icon {
            Ok(tray) => tray,
            Err(e) => return Err((format!("tray build failed: {e}"), agent)),
        };

        // The shell mounted — run the agent core on its own thread. We hand it owned handles for the
        // status surface + shutdown BEFORE moving the agent into the thread.
        let status = agent.status_handle();
        let shutdown = agent.shutdown_handle();
        std::thread::spawn(move || agent.run());

        let quit_id = quit_item.id().clone();
        let lock_id = lock_item.id().clone();
        let menu_events = MenuEvent::receiver();

        // The event loop diverges; `_tray` + `session` stay alive on this frame for the whole process
        // (dropping `session` would drop the OS screen-lock subscription guard it holds).
        event_loop.run(move |_event, _target, control_flow| {
            *control_flow = ControlFlow::WaitUntil(Instant::now() + REFRESH);
            repaint(&status, &running_item, &engine_item, &profile_item);

            // Idle auto-lock: each tick, drop the DEK if the session has been idle past its timeout.
            if let Some(session) = &session {
                session.lock.poll_idle();
            }

            while let Ok(event) = menu_events.try_recv() {
                // Any tray interaction is activity — postpone the idle auto-lock.
                if let Some(session) = &session {
                    session.lock.note_activity();
                }
                if event.id == lock_id {
                    if let Some(session) = &session {
                        session.lock.lock_now();
                    }
                } else if event.id == quit_id {
                    shutdown.trigger();
                    wait_for_stop(&status);
                    *control_flow = ControlFlow::Exit;
                }
            }
        });
    }

    /// Repaint the tray menu labels from the latest agent status.
    fn repaint(
        status: &SharedStatus,
        running_item: &MenuItem,
        engine_item: &MenuItem,
        profile_item: &MenuItem,
    ) {
        let Ok(status) = status.read() else { return };
        running_item.set_text(if status.running {
            "DIG — running"
        } else {
            "DIG — stopped"
        });
        engine_item.set_text(match &status.engine {
            EngineState::Connected => "Engine: connected",
            EngineState::Disconnected { .. } => "Engine: not connected",
        });
        profile_item.set_text(match &status.active_profile {
            Some(p) => format!("Profile: {}", p.did),
            None => "Profile: (none)".to_string(),
        });
    }

    /// Give the agent thread a brief window to flush its config and mark itself stopped before the
    /// event loop exits the process.
    fn wait_for_stop(status: &SharedStatus) {
        let deadline = Instant::now() + GRACEFUL_STOP;
        while Instant::now() < deadline {
            if !status.read().map(|s| s.running).unwrap_or(false) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A small solid-color brand icon (DIG accent) generated in code, so the binary carries no
    /// external asset. A richer branded icon is wired by the dig-installer packaging (U8).
    fn brand_icon() -> Icon {
        const SIZE: u32 = 32;
        // DIG dark-theme accent (teal-green), fully opaque.
        const PIXEL: [u8; 4] = [0x12, 0x9E, 0x76, 0xFF];
        let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
        for _ in 0..(SIZE * SIZE) {
            rgba.extend_from_slice(&PIXEL);
        }
        Icon::from_rgba(rgba, SIZE, SIZE).expect("a solid-color icon is always valid")
    }
}
