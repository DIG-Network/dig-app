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
//! The node connection is live ([`NodeConnector`], dig_ecosystem#949): on every tick the agent walks
//! the §5.3 endpoint ladder and asks a running dig-node for `control.status` over its loopback
//! JSON-RPC surface, so the tray shows the node's real version, cache and hosted-store counts — and,
//! when no node is running, says so with the reason rather than spinning.

#[cfg(feature = "tray")]
use dig_app_core::account::boot::{
    account_exists, boot_existing_account, open_account, reboot_reunlock, BootedAccount,
};
#[cfg(feature = "tray")]
use dig_app_core::account::journey::WindowedPresenter;
#[cfg(feature = "tray")]
use dig_app_core::account::lifecycle::Seeding;
#[cfg(feature = "tray")]
use dig_app_core::account::residency::AccountResidency;
#[cfg(feature = "tray")]
use dig_app_core::account::ProfileIx;
use dig_app_core::agent::Agent;
#[cfg(feature = "tray")]
use dig_app_core::confirm::{native_confirmer, NativeConfirmer, NoticePrompt};
use dig_app_core::engine::NodeConnector;
use dig_app_core::environment::AppEnvironment;
use dig_app_core::form_factor::FormFactor;
#[cfg(feature = "tray")]
use dig_app_core::loopback::SignReauthGate;
#[cfg(feature = "tray")]
use dig_app_core::session_lock::{
    panic_safe_lock_callback, PlatformScreenLockSource, ScreenLockGuard, ScreenLockSource,
    SessionLock, SystemClock, DEFAULT_IDLE_TIMEOUT,
};
#[cfg(feature = "tray")]
use dig_app_core::sign_service::{SessionReauthGate, TraySessionLock};
#[cfg(feature = "tray")]
use dig_app_core::storage::did_hash;
#[cfg(feature = "tray")]
use dig_app_core::tray_menu::AccountState;
use dig_app_core::Os;
#[cfg(feature = "tray")]
use dig_app_core::{sign_service, storage};
#[cfg(feature = "tray")]
use std::sync::Arc;

/// The live session-lock wiring the tray drives once the APP-SIGN channel is up: the shared
/// [`SessionLock`] (lock-now / idle poll / OS screen-lock all act on it, and the sign path
/// re-authenticates through it) plus the OS screen-lock subscription guard, kept alive for as long as
/// the tray runs.
#[cfg(feature = "tray")]
struct TraySession {
    lock: TraySessionLock,
    _screen_guard: Box<dyn ScreenLockGuard>,
    /// The live account behind this session, so the tray can address its phrase vault. Held here
    /// because [`SessionLock`] deliberately exposes only lock/unlock, not the keys it guards.
    residency: AccountResidency,
    /// What the tray must tell the user about this account: its root profile id, and whether it has a
    /// recovery phrase at all. Carried here (not re-read each repaint) because both are fixed for the
    /// life of an unlocked account and reading them per-tick would touch the disk 120 times a minute.
    account: AccountFacts,
}

/// The user-visible facts about the account behind a live session.
#[derive(Clone)]
#[cfg(feature = "tray")]
struct AccountFacts {
    /// The root profile's stable id (the seed-derived identity key in hex, until the DID mint lands).
    profile_id: String,
    /// Whether a recovery phrase is stored — `false` = enrolled before phrases existed, so the account
    /// cannot be recovered from words and the tray says so.
    recoverable: bool,
}

fn main() {
    // Install the shared logging stack FIRST, before anything else can emit an event that would
    // otherwise be silently dropped. Held for the whole process lifetime; see `logging`'s docs for
    // why a plain local guard is enough here (this is the crate's one entrypoint).
    let _log_guard = dig_app::logging::init();

    let version = env!("CARGO_PKG_VERSION");
    let env = resolve_environment();
    tracing::info!(version, os = ?env.os, has_display = env.has_display, "dig-app starting");

    let agent = match Agent::from_env(&env, NodeConnector::default()) {
        Ok(agent) => agent,
        Err(e) => {
            tracing::error!(error = %e, "dig-app cannot start");
            eprintln!("dig-app {version}: cannot start — {e}");
            std::process::exit(1);
        }
    };
    // Name the endpoints that WILL be tried, not a single guessed address: the agent resolves the
    // §5.3 ladder on each probe, so "which node?" is only answered once one answers.
    let ladder = dig_app_core::control::endpoint_ladder(Some(agent.endpoint())).join(", ");
    tracing::info!(node_endpoints = %ladder, "node endpoint ladder resolved");
    eprintln!("dig-app {version} — user identity agent starting (looking for a node at: {ladder})");

    match env.form_factor() {
        FormFactor::Tray => {
            // A desktop session is present, so the terminal native-confirm gate is available — bring
            // the APP-SIGN extension↔dig-app signing channel live (best-effort; see the fn's docs).
            // A live channel hands back the session-lock the tray drives (lock-now / idle / OS lock).
            //
            // A `--no-default-features` (headless) build has no tray, no confirm windows and therefore
            // no way for a human to authorize a signature, so it starts no signing channel at all
            // rather than one that could only ever fail closed.
            #[cfg(feature = "tray")]
            let tray_session = start_sign_service(&env);
            #[cfg(not(feature = "tray"))]
            let tray_session = None::<()>;
            run_tray_or_headless(agent, tray_session, env)
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
fn run_tray_or_headless(
    agent: Agent<NodeConnector>,
    #[cfg(feature = "tray")] session: Option<TraySession>,
    #[cfg(not(feature = "tray"))] session: Option<()>,
    env: AppEnvironment,
) {
    #[cfg(feature = "tray")]
    match tray::run(agent, session, env) {
        // The event loop owns the process once mounted, so this arm is unreachable in practice.
        Ok(()) => {}
        // `run` returns only on the degrade path, handing the agent back so we can serve headless.
        Err((reason, agent)) => {
            report_tray_unavailable(&reason, env_os_of(&agent));
            agent.run();
        }
    }
    #[cfg(not(feature = "tray"))]
    {
        let _ = session;
        // A headless BUILD is a deliberate choice, not a failure, so it is stated plainly and without
        // the "install a tray library" advice that would only mislead here.
        tracing::info!("built without the tray feature — running as headless agent");
        eprintln!(
            "dig-app: this is the headless build — there is no menu. Use `dign` for your account \
             (`dign account status`, `dign account restore`)."
        );
        let _ = env;
        agent.run();
    }
}

/// Report a tray that could not be mounted, on BOTH channels a person might look at.
///
/// An unmountable tray is the app's most dangerous failure mode because it is INVISIBLE: the process
/// runs, reports healthy, and every account surface is unreachable (see
/// [`tray_unavailable_advice`](dig_app_core::tray_menu::tray_unavailable_advice) for why Linux hits this
/// silently). So it is logged at WARN — a level a bug-report bundle keeps — and printed to stderr, with
/// the cause and the `dign` way in.
#[cfg(feature = "tray")]
fn report_tray_unavailable(reason: &str, os: Os) {
    let advice = dig_app_core::tray_menu::tray_unavailable_advice(reason, os);
    tracing::warn!(
        reason,
        ?os,
        "tray could not be mounted — the DIG menu is not reachable"
    );
    eprintln!("dig-app: {advice}");
}

/// The OS the shell resolved, recovered for the degrade path.
///
/// `tray::run` hands the agent back but not the environment (it moved it), and the advice text needs the
/// platform. Re-deriving it from the compile target is exact — this is the same mapping
/// [`current_os`] uses, and a binary cannot change platform at runtime.
#[cfg(feature = "tray")]
fn env_os_of<T>(_agent: &T) -> Os {
    current_os()
}

/// Bring the APP-SIGN loopback signing channel live on boot (dig_ecosystem#958, `SPEC.md` §5.6).
///
/// The signing channel needs TWO things a headless / locked host cannot provide, so this is
/// deliberately best-effort and fail-closed — it starts the server only when both hold, and simply
/// logs + returns otherwise (never blocks or crashes the shell):
///
/// 1. **An unlocked master-HD account** — the injected live-view signer + sealer read the master seed
///    from the [`AccountResidency`]. Only Windows/macOS can unlock zero-prompt via the OS credential
///    store; Linux needs a user passphrase (a UX not yet wired), so the channel defers there.
/// 2. **A desktop session** — guaranteed here because this runs only on the [`FormFactor::Tray`] path,
///    so the per-OS [`native_confirmer`] can raise a real biometric confirm.
///
/// When both hold it assembles the [`FrameRouter`](dig_app_core::loopback::FrameRouter) over the
/// account's default profile, wires the session-lock (WSEC-D, dig_ecosystem#967) so the sign path
/// re-authenticates after a lock, restores any persisted pairings/whitelist/nonce ledger, serves the
/// two loopback listeners on a background thread (the OS event loop keeps the main thread), and hands
/// the tray the [`TraySession`] it drives (lock-now / idle poll / OS screen-lock). Returns `None` on
/// any deferral.
#[cfg(feature = "tray")]
fn start_sign_service(env: &AppEnvironment) -> Option<TraySession> {
    // Zero-prompt unlock is only available where the OS credential store is the custody primary.
    if !matches!(env.os, Os::Windows | Os::MacOs) {
        tracing::info!("APP-SIGN loopback deferred: no zero-prompt account unlock on this OS yet");
        return None;
    }
    let brand_dir = match env.brand_dir() {
        Ok(dir) => dir,
        Err(e) => {
            tracing::warn!(error = %e, "APP-SIGN loopback not started: could not resolve the AppData directory");
            return None;
        }
    };

    // Unlock the master-HD account (#1547): the seed is sealed in a per-user file backend under the
    // OS-credential-store password, and housed in a lockable residency. The residency owns the sole
    // unlocked account; the live-view signer + sealer below read through it, so a tray lock relocks
    // them at once.
    //
    // This path NEVER enrols (dig_ecosystem#1752). A host with no account yet gets no session, and the
    // tray offers "Set up my DIG Account…" — because creating an account means showing a recovery
    // phrase, and a recovery-phrase window that appears unbidden at login is a window people click
    // away. Setup is something the user asks for.
    let booted = boot_existing_account(&brand_dir)?;
    let BootedAccount {
        residency,
        profile_id,
        recoverable,
    } = booted;

    // The session-lock the tray drives and the sign path re-authenticates through — the SAME shared
    // controller over the SAME account residency, so a lock the tray triggers is the lock the signer
    // and sealer see.
    let lock: TraySessionLock = Arc::new(SessionLock::new(
        residency.clone(),
        SystemClock::new(),
        DEFAULT_IDLE_TIMEOUT,
    ));

    let profile_dir = storage::profile_dir(&brand_dir, &did_hash(&profile_id));
    let confirmer: Arc<dyn dig_app_core::confirm::NativeConfirmer> = Arc::from(native_confirmer());
    let reauth_gate = build_reauth_gate(Arc::clone(&lock), brand_dir.clone(), residency.clone());
    // Inject the LIVE unlocked-account identity signer through the sign seam (#1547 flip): the
    // identity-sign path now runs through the real master-HD account (a `dig_account::ProfileSigner`
    // behind the residency's live view), replacing the retired ProfileSessionSigner. The sealer is
    // the residency's live-view AccountSealer over the profile's master-seed DEK — both relock the
    // instant the residency is locked.
    let signer: Box<dyn dig_app_core::session::SessionSigner + Send + Sync> =
        Box::new(residency.signer(ProfileIx::ROOT));
    let sealer = residency.production_sealer(ProfileIx::ROOT);
    let router = sign_service::build_router(sealer, &profile_id, &profile_dir, confirmer, signer)
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
        residency,
        _screen_guard: screen_guard,
        account: AccountFacts {
            profile_id,
            recoverable,
        },
    })
}

/// Where this host keeps its DIG data, or `None` if it cannot be resolved. A thin wrapper so the tray's
/// account actions and [`start_sign_service`] name the same directory.
#[cfg(feature = "tray")]
fn brand_dir(env: &AppEnvironment) -> Option<std::path::PathBuf> {
    env.brand_dir()
        .map_err(|e| tracing::warn!(error = %e, "could not resolve the DIG data directory"))
        .ok()
}

/// The account state the tray shows, derived from what actually exists on this host.
///
/// The three inputs are genuinely different situations and the user is told which one they are in: a
/// host that cannot hold an account at all, an account that exists but did not unlock, and a live one.
#[cfg(feature = "tray")]
fn account_state(env: &AppEnvironment, session: Option<&TraySession>) -> AccountState {
    if !matches!(env.os, Os::Windows | Os::MacOs) {
        return AccountState::Unsupported;
    }
    match session {
        Some(session) => AccountState::Unlocked {
            recoverable: session.account.recoverable,
        },
        None => match brand_dir(env) {
            Some(dir) if account_exists(&dir) => AccountState::Locked,
            _ => AccountState::Absent,
        },
    }
}

/// Create a brand-new account: generate a recovery phrase, show it once, confirm retention, enrol.
///
/// Returns the live session on success. On any refusal or failure it returns `None` and tells the user
/// what happened — never silently, because the user pressed a button and is waiting for an answer.
#[cfg(feature = "tray")]
fn set_up_account(env: &AppEnvironment, confirmer: &dyn NativeConfirmer) -> Option<TraySession> {
    let dir = brand_dir(env)?;
    let presenter = WindowedPresenter::new(confirmer);
    if open_account(&dir, Seeding::NewPhrase(&presenter)).is_none() {
        notify(
            confirmer,
            "DIG — Setup not completed",
            "Your DIG Account was not created.",
            "Nothing was changed on this computer. You can start again from the DIG tray menu \
             whenever you are ready.",
        );
        return None;
    }
    // Re-open through the normal boot path so the session, signer, sealer and screen-lock guard are
    // assembled exactly as they are on every other start — one code path, no special-cased first run.
    let session = start_sign_service(env);
    if session.is_some() {
        notify(
            confirmer,
            "DIG — Account ready",
            "Your DIG Account is set up.",
            "You can view your recovery phrase again at any time from the DIG tray menu.",
        );
    }
    session
}

/// Tell the user how to restore an account from their recovery phrase.
///
/// The tray cannot take 24 words as input — a system-tray menu has no text field, and typing a recovery
/// phrase into an OS message box is not something the platform offers. So the restore lives in the
/// `dign` CLI, and this window hands over the exact command rather than leaving the user to search for
/// it (§6.1: point at the way forward, never a dead end).
#[cfg(feature = "tray")]
fn explain_restore(confirmer: &dyn NativeConfirmer) {
    notify(
        confirmer,
        "DIG — Restore from a recovery phrase",
        "Restoring an account is done from the command line.",
        "Open a terminal and run:\n\n    dign account restore\n\nIt will ask for your 24 words, \
         privately, and will not echo them. When it finishes, restart DIG and your account will be \
         here.\n\nThis machine currently has no DIG Account, so nothing will be overwritten.",
    );
}

/// Draw a plain informational window. A helper so every one of the tray's messages goes through the same
/// OS-owned surface rather than a mix of dialogs, notifications and silence.
#[cfg(feature = "tray")]
fn notify(confirmer: &dyn NativeConfirmer, title: &str, heading: &str, body: &str) {
    confirmer.show_notice(&NoticePrompt {
        title,
        heading,
        body,
        acknowledge: "OK",
    });
}

/// The production sign-path re-auth gate: on a sign after a lock it re-unlocks the account (a
/// zero-prompt re-unlock from the OS credential store) and re-installs it into the shared `residency`
/// before the signature proceeds — restoring the live-view signer so the pending sign can complete
/// (dig_ecosystem#967 / #1547). A failed re-unlock leaves the residency locked, so the sign is refused.
#[cfg(feature = "tray")]
fn build_reauth_gate(
    lock: TraySessionLock,
    brand_dir: std::path::PathBuf,
    residency: AccountResidency,
) -> Arc<dyn SignReauthGate> {
    Arc::new(SessionReauthGate::new(lock, move || {
        reboot_reunlock(&brand_dir, &residency)
    }))
}

/// Resolve the real per-user host facts the agent boots from — shared with `dign` so both shells
/// address the identical per-user directory ([`AppEnvironment::from_host`]).
fn resolve_environment() -> AppEnvironment {
    AppEnvironment::from_host()
}

/// The OS this build targets, for the tray-unavailable advice text.
fn current_os() -> Os {
    if cfg!(target_os = "windows") {
        Os::Windows
    } else if cfg!(target_os = "macos") {
        Os::MacOs
    } else {
        Os::Linux
    }
}

/// The desktop tray / menu-bar shell. Compiled only with the default `tray` feature; a headless
/// build omits it entirely.
///
/// The shell is deliberately dumb about WHAT the menu should contain: it asks
/// [`dig_app_core::tray_menu::build`] for a [`MenuModel`] and renders it, so every rule about which items
/// appear and when lives in one unit-tested place (dig_ecosystem#1752). What lives here is only the two
/// things that cannot be tested without a desktop: turning rows into native menu items, and running each
/// [`TrayAction`]'s handler.
#[cfg(feature = "tray")]
mod tray {
    use super::{
        account_state, explain_restore, notify, set_up_account, start_sign_service, AppEnvironment,
        TraySession,
    };
    use dig_app_core::account::boot::vault_for;
    use dig_app_core::account::journey::{explain_missing_phrase, reveal_phrase};
    use dig_app_core::agent::{Agent, SharedStatus};
    use dig_app_core::confirm::{native_confirmer, NativeConfirmer};
    use dig_app_core::engine::NodeConnector;
    use dig_app_core::tray_menu::{self, MenuModel, MenuRow, TrayAction, TrayView};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

    /// How long to let the agent thread flush + stop after "Quit" before the loop exits the process.
    const GRACEFUL_STOP: Duration = Duration::from_secs(1);
    /// How often the tray re-reads the agent status and, if anything changed, repaints its menu.
    const REFRESH: Duration = Duration::from_millis(500);

    /// A rendered menu plus the map from each native item id back to the action it stands for.
    ///
    /// The map is what lets the shell stay ignorant of the menu's shape: a click arrives as an opaque
    /// [`MenuId`], and this translates it into the [`TrayAction`] the model named.
    struct RenderedMenu {
        menu: Menu,
        actions: HashMap<MenuId, TrayAction>,
    }

    /// Turn a [`MenuModel`] into a native menu.
    ///
    /// Returns an error string (not a panic) if the platform refuses an item, so a menu that cannot be
    /// built degrades the shell to headless rather than killing the process.
    fn render(model: &MenuModel) -> Result<RenderedMenu, String> {
        let menu = Menu::new();
        let mut actions = HashMap::new();
        for row in &model.rows {
            match row {
                MenuRow::Status(text) => {
                    // Status rows are disabled items: they read as text, and cannot be clicked.
                    menu.append(&MenuItem::new(text, false, None))
                        .map_err(|e| format!("menu status row failed: {e}"))?;
                }
                MenuRow::Separator => menu
                    .append(&PredefinedMenuItem::separator())
                    .map_err(|e| format!("menu separator failed: {e}"))?,
                MenuRow::Action {
                    action,
                    label,
                    enabled,
                } => {
                    let item = MenuItem::new(label, *enabled, None);
                    actions.insert(item.id().clone(), *action);
                    menu.append(&item)
                        .map_err(|e| format!("menu action row failed: {e}"))?;
                }
            }
        }
        Ok(RenderedMenu { menu, actions })
    }

    /// Read the current state of the world into the one snapshot the menu is built from.
    fn snapshot(
        status: &SharedStatus,
        env: &AppEnvironment,
        session: Option<&TraySession>,
    ) -> TrayView {
        let account = account_state(env, session);
        let (running, node, did) = match status.read() {
            Ok(status) => (
                status.running,
                status.engine.summary(),
                status.active_profile.as_ref().map(|p| p.did.clone()),
            ),
            // A poisoned status lock is not a reason to show a blank menu: say what we can, and let the
            // rest read as "starting".
            Err(_) => (false, "Node: status unavailable".to_string(), None),
        };
        TrayView {
            running,
            node,
            account: Some(account),
            profile_id: session.map(|s| s.account.profile_id.clone()),
            did,
        }
    }

    /// Mount the tray over `agent` and run the platform event loop. The tray is built FIRST (that is
    /// what fails on a display-less host); only once it mounts do we spawn the agent's blocking run
    /// loop on a background thread, leaving the OS event loop on the main thread (required on macOS).
    ///
    /// On success the event loop owns the process for its lifetime and this never returns. On
    /// failure it hands `agent` back in the `Err` so the caller can still run it headless.
    #[allow(clippy::result_large_err)]
    pub fn run(
        agent: Agent<NodeConnector>,
        session: Option<TraySession>,
        env: AppEnvironment,
    ) -> Result<(), (String, Agent<NodeConnector>)> {
        let event_loop = EventLoopBuilder::new().build();
        let status = agent.status_handle();

        let mut model = snapshot(&status, &env, session.as_ref());
        let mut menu = match render(&tray_menu::build(&model)) {
            Ok(rendered) => rendered,
            Err(e) => return Err((e, agent)),
        };

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu.menu.clone()))
            .with_tooltip("DIG — user identity agent")
            .with_icon(brand_icon())
            .build();
        let tray: TrayIcon = match tray_icon {
            Ok(tray) => tray,
            Err(e) => return Err((format!("tray build failed: {e}"), agent)),
        };

        // The shell mounted — run the agent core on its own thread. We hand it owned handles for the
        // status surface + shutdown BEFORE moving the agent into the thread.
        let shutdown = agent.shutdown_handle();
        std::thread::spawn(move || agent.run());

        let menu_events = MenuEvent::receiver();
        // ONE confirmer for the whole shell: every account window (setup, reveal, the explainers) is
        // drawn by the same OS-owned, biometric-backed surface the signing path uses.
        let confirmer: Box<dyn NativeConfirmer> = native_confirmer();
        let mut session = session;

        // The event loop diverges; `tray` + `session` stay alive on this frame for the whole process
        // (dropping `session` would drop the OS screen-lock subscription guard it holds).
        event_loop.run(move |_event, _target, control_flow| {
            *control_flow = ControlFlow::WaitUntil(Instant::now() + REFRESH);

            // Idle auto-lock: each tick, drop the DEK if the session has been idle past its timeout.
            if let Some(session) = &session {
                session.lock.poll_idle();
            }

            while let Ok(event) = menu_events.try_recv() {
                // Any tray interaction is activity — postpone the idle auto-lock.
                if let Some(session) = &session {
                    session.lock.note_activity();
                }
                let Some(action) = menu.actions.get(&event.id).copied() else {
                    continue;
                };
                if dispatch(
                    action,
                    &mut session,
                    &env,
                    confirmer.as_ref(),
                    &shutdown,
                    &status,
                ) {
                    *control_flow = ControlFlow::Exit;
                    return;
                }
            }

            // Repaint only when something actually changed: rebuilding a native menu every 500ms would
            // close the menu under the user's cursor while they are reading it.
            let latest = snapshot(&status, &env, session.as_ref());
            if !view_eq(&latest, &model) {
                if let Ok(rendered) = render(&tray_menu::build(&latest)) {
                    tray.set_menu(Some(Box::new(rendered.menu.clone())));
                    menu = rendered;
                    model = latest;
                }
            }
        });
    }

    /// Whether two snapshots would render the same menu. [`TrayView`] is not `PartialEq` (it is a
    /// display model whose equality is only ever this question), so the comparison is spelled out.
    fn view_eq(a: &TrayView, b: &TrayView) -> bool {
        a.running == b.running
            && a.node == b.node
            && a.account == b.account
            && a.profile_id == b.profile_id
            && a.did == b.did
    }

    /// Run one menu action. Returns `true` when the process should exit.
    ///
    /// Every arm ends in something the user can see — a window, a new menu state, or the app closing.
    /// A handler that silently did nothing would leave a person clicking a menu item that appears
    /// broken, which is the failure mode §6.1 exists to prevent.
    fn dispatch(
        action: TrayAction,
        session: &mut Option<TraySession>,
        env: &AppEnvironment,
        confirmer: &dyn NativeConfirmer,
        shutdown: &dig_app_core::shutdown::Shutdown,
        status: &SharedStatus,
    ) -> bool {
        match action {
            TrayAction::SetUpAccount => {
                if session.is_none() {
                    *session = set_up_account(env, confirmer);
                }
            }
            TrayAction::RestoreFromPhrase => explain_restore(confirmer),
            TrayAction::Unlock => {
                // The account exists but did not unlock at boot. Re-running the boot path is the whole
                // unlock: on Windows/macOS it is zero-prompt from the OS credential store.
                *session = start_sign_service(env);
                if session.is_none() {
                    notify(
                        confirmer,
                        "DIG — Could not unlock",
                        "Your DIG Account could not be unlocked.",
                        "The stored password for this account could not be read from the system \
                         credential store. The log folder (in this menu) has the details.",
                    );
                }
            }
            TrayAction::LockNow => {
                if let Some(session) = session {
                    session.lock.lock_now();
                }
            }
            TrayAction::ShowRecoveryPhrase => show_phrase(session.as_ref(), env, confirmer),
            TrayAction::FixMissingPhrase => {
                explain_missing_phrase(confirmer);
            }
            TrayAction::CopyDigId => copy_dig_id(session.as_ref(), confirmer),
            TrayAction::CreateDid => explain_did_mint(confirmer),
            TrayAction::OpenLogs => open_log_folder(confirmer),
            TrayAction::Quit => {
                shutdown.trigger();
                wait_for_stop(status);
                return true;
            }
        }
        false
    }

    /// Re-display the account's recovery phrase, behind the OS re-authentication gate.
    fn show_phrase(
        session: Option<&TraySession>,
        env: &AppEnvironment,
        confirmer: &dyn NativeConfirmer,
    ) {
        use dig_app_core::account::journey::RevealOutcome;

        // `vault_for` returns `None` on a locked account, so an idle auto-lock between opening the menu
        // and clicking the item lands in the "locked" branch below rather than revealing anything.
        let vault = super::brand_dir(env)
            .zip(session)
            .and_then(|(dir, session)| vault_for(&dir, &session.residency));
        let Some(vault) = vault else {
            notify(
                confirmer,
                "DIG — Recovery phrase",
                "Your DIG Account is locked.",
                "Unlock it from this menu first, then try again.",
            );
            return;
        };
        match reveal_phrase(confirmer, &vault) {
            RevealOutcome::Shown | RevealOutcome::Refused => {}
            RevealOutcome::NoPhraseStored => {
                explain_missing_phrase(confirmer);
            }
            RevealOutcome::Unavailable => notify(
                confirmer,
                "DIG — Recovery phrase",
                "Your recovery phrase could not be read.",
                "Your account is fine and still works. The log folder (in this menu) has the details.",
            ),
        }
    }

    /// Put the profile's DIG ID on the clipboard, telling the user either way.
    ///
    /// The clipboard write goes through the platform's own utility rather than pulling a clipboard
    /// crate into the shell for one string; if it is unavailable the id is shown instead, so the user
    /// can still copy it by hand rather than being told "no".
    fn copy_dig_id(session: Option<&TraySession>, confirmer: &dyn NativeConfirmer) {
        let Some(session) = session else { return };
        let id = &session.account.profile_id;
        if write_clipboard(id) {
            notify(
                confirmer,
                "DIG — DIG ID copied",
                "Your DIG ID is on the clipboard.",
                id,
            );
        } else {
            notify(
                confirmer,
                "DIG — Your DIG ID",
                "Here is your DIG ID (select it to copy).",
                id,
            );
        }
    }

    /// Write `text` to the OS clipboard via the platform utility. Returns whether it succeeded.
    fn write_clipboard(text: &str) -> bool {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut command = if cfg!(target_os = "windows") {
            let mut c = Command::new("cmd");
            c.args(["/C", "clip"]);
            c
        } else if cfg!(target_os = "macos") {
            Command::new("pbcopy")
        } else {
            let mut c = Command::new("xclip");
            c.args(["-selection", "clipboard"]);
            c
        };
        let Ok(mut child) = command.stdin(Stdio::piped()).spawn() else {
            return false;
        };
        let written = child
            .stdin
            .as_mut()
            .map(|stdin| stdin.write_all(text.as_bytes()).is_ok())
            .unwrap_or(false);
        written && child.wait().map(|s| s.success()).unwrap_or(false)
    }

    /// What the user is told when they ask for an on-chain DID.
    ///
    /// Minting a `did:chia:` is a real mainnet spend, and `dig-account`'s minter is still a Phase-2
    /// stub, so this NEVER spends and never pretends to. It says what a DID is for, that it costs money,
    /// and that the account works fully without one — which is true, and is the honest alternative to a
    /// button that fails obscurely (§3.7).
    fn explain_did_mint(confirmer: &dyn NativeConfirmer) {
        notify(
            confirmer,
            "DIG — On-chain DID",
            "An on-chain DID is optional, and it costs XCH.",
            "A DID publishes your identity on the Chia blockchain so others can find and verify it. \
             Creating one is a real transaction that spends real XCH from your DIG Account, so DIG \
             will never create one without you asking.\n\n\
             Your account, your recovery phrase and your address all work fully without a DID. \
             On-chain minting is not available in this version yet — when it is, this is where you \
             will start it, and you will see the exact cost before anything is spent.",
        );
    }

    /// Open the log folder in the platform file manager — the escape hatch when the menu cannot explain
    /// what went wrong.
    fn open_log_folder(confirmer: &dyn NativeConfirmer) {
        let dir = dig_app::logging::log_dir();
        let opener = if cfg!(target_os = "windows") {
            "explorer"
        } else if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        if std::process::Command::new(opener)
            .arg(&dir)
            .spawn()
            .is_err()
        {
            notify(
                confirmer,
                "DIG — Logs",
                "DIG could not open the folder for you.",
                &format!("The logs are here:\n\n{}", dir.display()),
            );
        }
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
