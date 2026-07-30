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
//!
//! # Why this is a GUI-subsystem binary (dig_ecosystem#1797)
//!
//! `windows_subsystem = "windows"` is what stops Windows allocating a console for a tray application: at
//! subsystem 3 (`WINDOWS_CUI`, what this shipped as through 3.4.0) a black console window appeared at every
//! launch AND the tray's lifetime was tied to it, so closing the console killed the agent. WireGuard's tray
//! app on the same machine is subsystem 2; `dig-node` is 3 and correctly so, being a service and a CLI.
//!
//! The consequence is that this process has **no console**, so the informational paths below attach to
//! their launcher's one before printing ([`dig_app::console`]) — `dig-app --version` is health-gated by the
//! update beacon and must still put exactly one line on stdout. `tests/gui_subsystem.rs` parses the built
//! binary's PE header and fails if the subsystem regresses.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(feature = "tray")]
use dig_app_core::account::boot::{
    account_exists, boot_existing_account, discard_account, open_account, reboot_reunlock,
    vault_for, BootedAccount, DiscardOutcome,
};
#[cfg(feature = "tray")]
use dig_app_core::account::journey::{
    ask_for_phrase, AccountCustodian, Replacement, WindowedPresenter,
};
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
use dig_app_core::tray_menu::{self, AccountState, AtRest, SessionFacts};
#[cfg(feature = "tray")]
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
    // Answer `--version`/`--help` BEFORE anything else — before the logging stack, before the agent,
    // before any tray. Two reasons this ordering is load-bearing:
    //
    //  * The update beacon health-gates this component by spawning `dig-app --version` and reading
    //    STDOUT (dig_ecosystem#1749). Anything else printed there, or any side effect that starts the
    //    agent, breaks the gate — so the informational paths return without touching the world.
    //  * Installing the logging stack first would create log files just to answer "what version are
    //    you?", on every single update check.
    let unrecognized = match dig_app::argv::parse(&std::env::args().skip(1).collect::<Vec<_>>()) {
        dig_app::argv::Invocation::Version => {
            // This binary is GUI-subsystem, so it has no console of its own and `println!` would go
            // nowhere. Attaching to the launcher's console is what keeps `dig-app --version` answerable
            // from a real terminal; a REDIRECTED stdout (how the update beacon reads it) is left untouched
            // — see `dig_app::console` for why that distinction is load-bearing.
            dig_app::console::attach_to_parent();
            println!("{}", dig_app::argv::version_line());
            return;
        }
        dig_app::argv::Invocation::Help => {
            dig_app::console::attach_to_parent();
            println!("{}", dig_app::argv::help_text());
            return;
        }
        dig_app::argv::Invocation::Run { unrecognized } => unrecognized,
    };

    // Install the shared logging stack FIRST, before anything else can emit an event that would
    // otherwise be silently dropped. Held for the whole process lifetime; see `logging`'s docs for
    // why a plain local guard is enough here (this is the crate's one entrypoint).
    let _log_guard = dig_app::logging::init();

    // An argument we did not understand never stops the agent, but it is never swallowed either: a
    // launcher passing a flag that silently does nothing is exactly how a misconfiguration hides.
    if !unrecognized.is_empty() {
        tracing::warn!(
            arguments = ?unrecognized,
            "ignoring unrecognized command-line arguments — run `dig-app --help` for the supported options"
        );
    }

    let version = dig_app::argv::version();
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

/// Whether an account exists at rest on this host — the cheap, side-effect-free half of "is this account
/// wedged?", asked only when there is no live session to ask instead.
#[cfg(feature = "tray")]
fn account_is_enrolled(env: &AppEnvironment) -> bool {
    brand_dir(env).is_some_and(|dir| account_exists(&dir))
}

/// The account state the tray shows: read the impure host facts, then let the tested rules decide.
///
/// The lock state is read FRESH from the residency on every repaint via [`SessionFacts::of`], never
/// inferred from the session existing — a session deliberately outlives its key material (lock-now and
/// the idle auto-lock drop the keys and keep the session so the sign path can re-unlock into it). This
/// function therefore holds no logic of its own; [`tray_menu::account_state`] owns every rule, where it
/// is covered by tests rather than sitting untested in a binary.
#[cfg(feature = "tray")]
fn account_state(
    env: &AppEnvironment,
    session: Option<&TraySession>,
    boot_failed: bool,
) -> AccountState {
    let supported = matches!(env.os, Os::Windows | Os::MacOs);
    // Only worth a filesystem check when there is no session to ask: with one, the account provably
    // exists, and this runs on every repaint tick.
    let at_rest = match session {
        Some(_) => AtRest::Present,
        None if !brand_dir(env).is_some_and(|dir| account_exists(&dir)) => AtRest::None,
        // An account IS here and we tried to open it and could not. Reporting this as merely `Locked` would
        // offer an `Unlock…` that is guaranteed to fail — the silent-signing-outage defect (#1799 review).
        None if boot_failed => AtRest::PresentButUnopenable,
        None => AtRest::Present,
    };
    let facts = session.map(|s| SessionFacts::of(&s.residency, s.account.recoverable));
    tray_menu::account_state(supported, at_rest, facts)
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

/// Restore an account onto a host that has none, from a recovery phrase typed into a native window.
///
/// **This replaces the terminal hand-off (dig_ecosystem#1798).** The tray used to show
/// *"Restore from a recovery phrase (in a terminal)…"* and print a `dign account restore` command, because
/// a tray menu has no text field. That is a property of the tray API, not a reason to send a person to a
/// console — and on a machine where dig-node's byte-identical `dign` alias wins the shared bin directory
/// (dig_ecosystem#1788) it handed them the WRONG TOOL. The words are now typed into a real OS window.
///
/// Returns the live session on success, and `None` on any refusal or failure — always after telling the
/// user which, because they pressed a button and are waiting for an answer.
#[cfg(feature = "tray")]
fn restore_account(env: &AppEnvironment, confirmer: &dyn NativeConfirmer) -> Option<TraySession> {
    let dir = brand_dir(env)?;
    let phrase = ask_for_phrase(
        confirmer,
        "Restore your DIG Account from its recovery phrase.",
    )?;
    if open_account(&dir, Seeding::Restore(&phrase)).is_none() {
        notify(
            confirmer,
            "DIG — Restore did not complete",
            "Your DIG Account could not be restored.",
            "Nothing was changed on this computer. The log folder (in the DIG menu) has the details, \
             and you can try again from the DIG menu whenever you are ready.",
        );
        return None;
    }
    // Re-open through the normal boot path so the session, signer, sealer and screen-lock guard are
    // assembled exactly as on every other start — one code path, no special-cased restore.
    let session = start_sign_service(env);
    if session.is_some() {
        notify(
            confirmer,
            "DIG — Account restored",
            "Your DIG Account is back on this computer.",
            "You can view your recovery phrase again at any time from the DIG menu.",
        );
    }
    session
}

/// Draw a plain informational window. A helper so every one of the shell's own messages goes through the
/// same OS-owned surface rather than a mix of dialogs, notifications and silence.
///
/// The destructive-verb messages are NOT here — they live with the flow that decides them, in
/// [`dig_app_core::account::journey`], so they are covered by that flow's tests.
#[cfg(feature = "tray")]
fn notify(confirmer: &dyn NativeConfirmer, title: &str, heading: &str, body: &str) {
    confirmer.show_notice(&NoticePrompt {
        title,
        heading,
        body,
        acknowledge: "OK",
    });
}

/// The production sign-path re-auth gate: on a sign after a lock it re-unlocks the account (a zero-prompt
/// re-unlock from the OS credential store) and re-installs it into the shared `residency` before the
/// signature proceeds — restoring the live-view signer so the pending sign can complete
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

/// The shell's [`AccountCustodian`]: the four host effects a destructive account verb has.
///
/// **This type holds NO ordering logic.** Authorize, collect the replacement, lock, discard, enrol is
/// decided by [`journey::replace_account`] in `dig-app-core`, where it is unit-tested against a recording
/// custodian. That split is a review finding (dig_ecosystem#1799): while the ordering lived here, in a `bin`
/// target behind `#[cfg(feature = "tray")]`, no test could reach it — inverting one character so a REFUSED
/// destroy destroyed the account left the whole workspace green.
///
/// The live session sits behind a [`RefCell`] because the trait takes `&self` (the ordering must not be able
/// to swap the session out of turn) while these methods genuinely have to replace it.
#[cfg(feature = "tray")]
struct ShellCustodian<'a> {
    env: &'a AppEnvironment,
    confirmer: &'a dyn NativeConfirmer,
    brand_dir: std::path::PathBuf,
    /// The tray's live session, replaced in place as the account is locked, discarded and re-enrolled.
    session: std::cell::RefCell<&'a mut Option<TraySession>>,
}

#[cfg(feature = "tray")]
impl AccountCustodian for ShellCustodian<'_> {
    fn lock_current(&self) {
        // Taking the session drops the tray's handle on it; locking first drops the KEY MATERIAL, so the
        // residency is not holding a seed that is about to be deleted underneath it.
        if let Some(live) = self.session.borrow_mut().take() {
            live.lock.lock_now();
        }
    }

    fn discard(&self) -> DiscardOutcome {
        discard_account(&self.brand_dir)
    }

    fn enrol_new(&self) -> bool {
        let session = set_up_account(self.env, self.confirmer);
        let enrolled = session.is_some();
        **self.session.borrow_mut() = session;
        enrolled
    }

    fn enrol_from(&self, phrase: &dig_app_core::account::recovery::RecoveryPhrase) -> bool {
        if open_account(&self.brand_dir, Seeding::Restore(phrase)).is_none() {
            return false;
        }
        // Re-open through the normal boot path so the session, signer, sealer and screen-lock guard are
        // assembled exactly as on every other start — one code path, no special-cased restore.
        let session = start_sign_service(self.env);
        let live = session.is_some();
        **self.session.borrow_mut() = session;
        live
    }

    fn reopen(&self) {
        **self.session.borrow_mut() = start_sign_service(self.env);
    }
}

/// Run a destructive account verb through the core flow.
///
/// Everything this function does is ASSEMBLE: resolve the directory, find the phrase vault, build the
/// custodian, and hand all of it to [`journey::replace_account`]. The outcome is discarded here because every
/// branch of that flow already ends in a window the user acknowledged.
#[cfg(feature = "tray")]
fn replace_account(
    session: &mut Option<TraySession>,
    env: &AppEnvironment,
    confirmer: &dyn NativeConfirmer,
    what: Replacement,
) {
    let Some(dir) = brand_dir(env) else { return };
    let vault = session
        .as_ref()
        .and_then(|session| vault_for(&dir, &session.residency));
    let custodian = ShellCustodian {
        env,
        confirmer,
        brand_dir: dir,
        session: std::cell::RefCell::new(session),
    };
    dig_app_core::account::journey::replace_account(confirmer, &custodian, what, vault.as_ref());
}

/// Resolve the real per-user host facts the agent boots from — shared with `dign` so both shells
/// address the identical per-user directory ([`AppEnvironment::from_host`]).
fn resolve_environment() -> AppEnvironment {
    AppEnvironment::from_host()
}

/// The OS this build targets, for the tray-unavailable advice text.
///
/// Only the tray shell renders that advice, so a headless build has no caller — gated to keep
/// `--no-default-features` free of dead-code warnings.
#[cfg(feature = "tray")]
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
/// appear and when lives in one unit-tested place (dig_ecosystem#1752). What lives here is only what
/// genuinely cannot run without a desktop: turning rows into native menu items, the platform event loop,
/// and running each [`TrayAction`]'s handler — all of it guarded by
/// [`dig_app::tray_guard::mount_or_degrade`], because the Linux desktop stack panics rather than failing
/// when a library is absent (dig_ecosystem#1756).
#[cfg(feature = "tray")]
mod tray {
    use super::{
        account_state, notify, replace_account, restore_account, set_up_account,
        start_sign_service, AppEnvironment, TraySession,
    };
    use dig_app::tray_guard::mount_or_degrade;
    use dig_app_core::account::boot::vault_for;
    use dig_app_core::account::journey::Replacement;
    use dig_app_core::account::journey::{
        explain_missing_phrase, explain_unopenable, reveal_phrase,
    };
    use dig_app_core::agent::{Agent, SharedStatus};
    use dig_app_core::confirm::{native_confirmer, NativeConfirmer};
    use dig_app_core::engine::NodeConnector;
    use dig_app_core::tray_menu::{self, MenuModel, MenuRow, TrayAction, TrayView};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
    use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

    /// How long to let the agent thread flush + stop after "Quit" before the loop exits the process.
    const GRACEFUL_STOP: Duration = Duration::from_secs(1);
    /// How often the tray re-reads the agent status and, if anything changed, repaints its menu.
    const REFRESH: Duration = Duration::from_millis(500);

    /// A rendered native menu plus the map from each native item id back to the action it stands for.
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
    ///
    /// This lives in the shell rather than the library on purpose: it does nothing but construct platform
    /// objects, and constructing them is not possible inside a test process — `muda` menus crash with
    /// `STATUS_ACCESS_VIOLATION` even from a `harness = false` main thread. Exercising it needs the real
    /// event loop, so it belongs with the event loop, where the coverage gate correctly excludes platform
    /// glue rather than inviting a test that only pretends to check it. Every RULE about what the menu
    /// contains is separately tested in [`dig_app_core::tray_menu`].
    fn render(model: &MenuModel) -> Result<RenderedMenu, String> {
        let menu = Menu::new();
        let mut actions = HashMap::new();
        append_rows(&menu, &model.rows, &mut actions)?;
        Ok(RenderedMenu { menu, actions })
    }

    /// Append `rows` to `parent`, recording each action row's native id in `actions`.
    ///
    /// Recursive because [`MenuRow::Submenu`] nests: the rare and destructive account verbs live one level
    /// down so the top level stays short (dig_ecosystem#1800). `muda`'s `Submenu` and `Menu` are different
    /// types with the same `append`, so the recursion is expressed over the [`ContainerMenu`] trait below
    /// rather than duplicated per level.
    fn append_rows(
        parent: &dyn ContainerMenu,
        rows: &[MenuRow],
        actions: &mut HashMap<MenuId, TrayAction>,
    ) -> Result<(), String> {
        for row in rows {
            match row {
                MenuRow::Separator => parent
                    .add(&PredefinedMenuItem::separator())
                    .map_err(|e| format!("menu separator failed: {e}"))?,
                MenuRow::Action {
                    action,
                    label,
                    enabled,
                } => {
                    let item = MenuItem::new(label, *enabled, None);
                    actions.insert(item.id().clone(), *action);
                    parent
                        .add(&item)
                        .map_err(|e| format!("menu action row failed: {e}"))?;
                }
                MenuRow::Submenu { label, rows } => {
                    // Enabled unconditionally: a submenu is not an action, and its own rows carry whatever
                    // gating applies. A greyed submenu would hide the way out of a bad state.
                    let submenu = Submenu::new(label, true);
                    append_rows(&submenu, rows, actions)?;
                    parent
                        .add(&submenu)
                        .map_err(|e| format!("menu submenu failed: {e}"))?;
                }
            }
        }
        Ok(())
    }

    /// Anything rows can be appended to — the root [`Menu`] or a [`Submenu`].
    ///
    /// `muda` gives both an inherent `append` rather than a shared trait, so this is the one-method bridge
    /// that lets [`append_rows`] recurse instead of being written once per nesting level.
    trait ContainerMenu {
        /// Append one already-built native item.
        fn add(&self, item: &dyn tray_icon::menu::IsMenuItem)
            -> Result<(), tray_icon::menu::Error>;
    }

    impl ContainerMenu for Menu {
        fn add(
            &self,
            item: &dyn tray_icon::menu::IsMenuItem,
        ) -> Result<(), tray_icon::menu::Error> {
            self.append(item)
        }
    }

    impl ContainerMenu for Submenu {
        fn add(
            &self,
            item: &dyn tray_icon::menu::IsMenuItem,
        ) -> Result<(), tray_icon::menu::Error> {
            self.append(item)
        }
    }

    /// Read the current state of the world into the one snapshot the menu is built from.
    fn snapshot(
        status: &SharedStatus,
        env: &AppEnvironment,
        session: Option<&TraySession>,
        boot_failed: bool,
    ) -> TrayView {
        use dig_app_core::engine::EngineState;

        let account = account_state(env, session, boot_failed);
        let (running, node, node_connected) = match status.read() {
            Ok(status) => (
                status.running,
                status.engine.summary(),
                // Read from the engine's own STATE, never sniffed out of the summary text: the icon and the
                // tooltip must not disagree with the engine because a message was reworded.
                matches!(status.engine, EngineState::Connected { .. }),
            ),
            // A poisoned status lock is not a reason to show a blank menu: say what we can, and let the
            // rest read as "starting".
            Err(_) => (
                false,
                "The node status could not be read.".to_string(),
                false,
            ),
        };
        TrayView {
            running,
            node,
            node_connected,
            account: Some(account),
            profile_id: session.map(|s| s.account.profile_id.clone()),
            // No on-chain DID can exist yet: minting is unimplemented, so there is nothing that could
            // have produced one. This was previously filled from `config.active_profile` — a LOCAL
            // string, not chain evidence — which would have made the tray report an on-chain identity
            // the user does not have as soon as anything started writing that field. See
            // [`TrayView::did`].
            did: None,
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

        // `boot_failed` is the observable half of a wedged account: an open was attempted and did not
        // produce a session. Sticky until an open SUCCEEDS, so the tray keeps telling the truth rather than
        // flickering back to "locked" on the next repaint tick.
        let mut boot_failed = session.is_none() && super::account_is_enrolled(&env);
        let mut model = snapshot(&status, &env, session.as_ref(), boot_failed);
        // Guarded for the same reason as the mount below: creating native menu objects touches the
        // platform's desktop stack, and a missing library there panics rather than failing.
        let mut menu = match mount_or_degrade(|| render(&tray_menu::build(&model))) {
            Ok(rendered) => rendered,
            Err(e) => return Err((e, agent)),
        };

        // The icon and tooltip are the tray's OTHER two surfaces, and since #1800 they are where the app's
        // state lives — the menu carries actions only. Both are set from the same snapshot the menu was
        // built from, so all three can never disagree.
        //
        // The icon is attached only if it decoded. A tray with no picture is still a working tray, so a bad
        // brand mark must never be the reason the user has no agent at all.
        let mut presence = tray_menu::status(&model);
        let mut builder = TrayIconBuilder::new()
            .with_menu(Box::new(menu.menu.clone()))
            .with_tooltip(&presence.tooltip);
        if let Some(icon) = brand_icon(presence.glyph) {
            builder = builder.with_icon(icon);
        }
        // Mounting is the step that touches the platform's tray library, and on Linux that library
        // PANICS when it is absent rather than returning an error (dig_ecosystem#1756) — which used to
        // kill the process outright, past every degrade path. Guarded so a missing desktop library costs
        // the user their tray, not their agent.
        let tray: TrayIcon = match mount_or_degrade(|| {
            builder
                .build()
                .map_err(|e| format!("tray build failed: {e}"))
        }) {
            Ok(tray) => tray,
            Err(e) => return Err((e, agent)),
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
            if session.is_some() {
                boot_failed = false;
            }
            let latest = snapshot(&status, &env, session.as_ref(), boot_failed);
            if !view_eq(&latest, &model) {
                // The icon and tooltip are refreshed BEFORE the menu, and unconditionally: they are the
                // only surfaces a user sees without clicking, so a failed menu rebuild (which keeps the old
                // menu, see `repaint`) must not also leave a stale picture. `set_icon`/`set_tooltip` touch
                // only the already-mounted tray, not the desktop's menu stack.
                let fresh = tray_menu::status(&latest);
                if fresh != presence {
                    show_presence(&tray, &fresh);
                    presence = fresh;
                }
                if let Some(rendered) = repaint(&tray, &tray_menu::build(&latest)) {
                    menu = rendered;
                    model = latest;
                }
            }
        });
    }

    /// Put the app's state on the tray's two non-menu surfaces: its picture and its hover text.
    ///
    /// Failures are logged and swallowed on purpose — a tooltip the platform refused is a cosmetic loss, and
    /// the `Status and details…` window says the same thing in full either way.
    fn show_presence(tray: &TrayIcon, presence: &tray_menu::TrayStatus) {
        if let Err(e) = tray.set_tooltip(Some(&presence.tooltip)) {
            tracing::warn!(error = %e, "the tray tooltip could not be updated");
        }
        if let Err(e) = tray.set_icon(brand_icon(presence.glyph)) {
            tracing::warn!(error = %e, "the tray icon could not be updated");
        }
    }

    /// Whether two snapshots would render the same menu. [`TrayView`] is not `PartialEq` (it is a
    /// display model whose equality is only ever this question), so the comparison is spelled out.
    fn view_eq(a: &TrayView, b: &TrayView) -> bool {
        a.running == b.running
            && a.node_connected == b.node_connected
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
            TrayAction::RestoreFromPhrase => {
                if session.is_none() {
                    *session = restore_account(env, confirmer);
                }
            }
            // The three destructive verbs. Each destroys the account here FIRST (behind the biometric
            // authorization gate) and then does whatever comes next, so they share one implementation and
            // differ only in what they promise the user afterwards.
            TrayAction::ReplaceWithNewAccount => {
                replace_account(session, env, confirmer, Replacement::WithNewAccount)
            }
            TrayAction::ReplaceFromPhrase => {
                replace_account(session, env, confirmer, Replacement::FromPhrase)
            }
            TrayAction::RemoveAccount => {
                replace_account(session, env, confirmer, Replacement::Nothing)
            }
            TrayAction::ShowStatus => show_status(status, env, session.as_ref(), confirmer),
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
            TrayAction::ExplainUnopenable => {
                explain_unopenable(confirmer);
            }
            TrayAction::FixMissingPhrase => {
                explain_missing_phrase(confirmer);
            }
            TrayAction::CopyDigId => copy_dig_id(session.as_ref(), confirmer),
            TrayAction::AboutDid => explain_did(confirmer),
            TrayAction::AboutWallet => explain_wallet(confirmer),
            TrayAction::Open => open_dig_link(status, confirmer),
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

    /// Show EVERYTHING the tray knows, in full, in a window that can hold it.
    ///
    /// This is where the five greyed status rows went (dig_ecosystem#1800), and the reason removing them
    /// lost nothing: a window has no width limit, so the engine's disconnected reason — the app's single
    /// most actionable message, naming the node to start or reinstall, and ~700 characters in the field —
    /// arrives whole instead of cut at 72.
    ///
    /// Re-snapshotted LIVE rather than read from the model the menu was built from, so a node that came up
    /// while the menu was open is reported as connected instead of replaying a stale reason.
    fn show_status(
        status: &SharedStatus,
        env: &AppEnvironment,
        session: Option<&TraySession>,
        confirmer: &dyn NativeConfirmer,
    ) {
        let view = snapshot(status, env, session, false);
        notify(
            confirmer,
            "DIG — Status",
            "This is what DIG is doing right now.",
            &tray_menu::details_text(&view),
        );
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

    /// What an on-chain DID is, what it would cost, and why the account is complete without one.
    ///
    /// Minting a `did:chia:` is a real mainnet spend and `dig-account`'s minter is still a Phase-2 stub, so
    /// the tray offers no way to mint one at all (see [`tray_menu::TrayAction::AboutDid`]). It offers this
    /// explanation instead, which is something it can actually deliver — the honest alternative both to a
    /// button that fails obscurely and to a permanently-greyed row (§3.7).
    fn explain_did(confirmer: &dyn NativeConfirmer) {
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

    /// Explain what the DIG wallet is, what it can do today, and what it cannot yet.
    ///
    /// This is the whole **Wallet** submenu for now, and that is deliberate. The tray offers no `Send` and
    /// no `Copy my receive address`, because it can perform neither: spending needs the money path (parked,
    /// dig_ecosystem#1702), and the address needs a field `TrayView` does not carry — it holds the identity
    /// public key, which is NOT a Chia address. A row that copied that string would hand someone the wrong
    /// value with total confidence, which is worse than no row.
    ///
    /// So the menu says what is true and names what is coming, rather than offering greyed verbs that
    /// cannot say when they will work (dig_ecosystem#1800, #1841).
    fn explain_wallet(confirmer: &dyn NativeConfirmer) {
        notify(
            confirmer,
            "DIG — Wallet",
            "Your DIG Account holds keys, and the wallet is being built around them.",
            "Your account already owns the keys a wallet needs — they were created with it, and your \
             recovery phrase restores them. What is not built yet is the part that USES them: showing \
             your balance, giving you an address to receive $DIG, and sending it.\n\n\
             DIG does not show you a balance it cannot verify, or an address it is not certain of, so \
             those are absent rather than shown as something you cannot click. When they work, they \
             will appear here.\n\n\
             Nothing about this affects reading DIG content — that never needs an account or a wallet.",
        );
    }

    /// Repaint the tray with a freshly-built menu, or leave the current one in place.
    ///
    /// Guarded by [`mount_or_degrade`] for the same reason the initial mount is: building native menu
    /// objects touches the platform's desktop stack, and on Linux a missing library there PANICS rather than
    /// failing (dig_ecosystem#1756). Without the guard the panic protection was startup-only, so a desktop
    /// that mounted successfully and then lost its indicator — or hit the library's intermittent dlopen
    /// failure on a later repaint — would still take the whole process down.
    ///
    /// A failed repaint is not fatal: the previously-rendered menu is still mounted and still correct about
    /// everything except the status lines, so the user keeps a working tray and the next tick tries again.
    fn repaint(tray: &TrayIcon, model: &MenuModel) -> Option<RenderedMenu> {
        match mount_or_degrade(|| render(model)) {
            Ok(rendered) => {
                tray.set_menu(Some(Box::new(rendered.menu.clone())));
                Some(rendered)
            }
            Err(e) => {
                tracing::warn!(error = %e, "tray repaint failed — keeping the menu already on screen");
                None
            }
        }
    }

    /// Open the log folder in the platform file manager — the escape hatch when the menu cannot explain
    /// what went wrong.
    /// Ask for a DIG link and open it through the local node (dig_ecosystem#1821).
    ///
    /// The tray equivalent of `dign open`, and the reason it exists: a tray-only user had no way to
    /// open a `chia://` or `urn:dig:chia:` link at all, and telling them to use a terminal is the
    /// pattern #1798 closed.
    ///
    /// Order matters and is deliberate:
    /// 1. **The node first.** With nothing to resolve through, asking for a link and *then* failing
    ///    wastes the user's typing. A refusal that names the reason beats a greyed menu row (§1800).
    /// 2. **`validate_open_link` before anything is built or opened.** Store content is
    ///    attacker-controlled (#745), so the scheme allowlist is a security boundary. Only
    ///    `chia://` and `urn:dig:chia:` reach the resolver.
    /// 3. **`link::serve_url` builds an `http://` URL under the NODE's own origin** — the host and
    ///    scheme are ours, never the user's, so a pasted link cannot redirect the browser elsewhere.
    /// 4. The browser is spawned with the URL as ONE argument, never through a shell.
    fn open_dig_link(status: &SharedStatus, confirmer: &dyn NativeConfirmer) {
        use dig_app_core::engine::EngineState;

        // 1. Is there a node to resolve through?
        let endpoint = match status.read() {
            Ok(s) => match &s.engine {
                EngineState::Connected { endpoint, .. } => endpoint.clone(),
                EngineState::Disconnected { reason } => {
                    notify(
                        confirmer,
                        "DIG — Open",
                        "DIG has no node to open content through.",
                        &format!(
                            "A DIG link is resolved by your local node, and none is reachable \
                             right now.\n\n{reason}\n\nOpen \"Status and details…\" to see what \
                             DIG is trying."
                        ),
                    );
                    return;
                }
            },
            Err(_) => {
                notify(
                    confirmer,
                    "DIG — Open",
                    "DIG could not read the node status.",
                    "Try again in a moment. If it keeps happening, the log folder has the detail.",
                );
                return;
            }
        };

        // 2. Ask for the link. Not secret, so neither masked nor revealable.
        let typed = match confirmer.request_input(&dig_app_core::confirm::InputPrompt {
            title: "DIG — Open",
            heading: "Which DIG link would you like to open?",
            body: "Paste a DIG link. Both forms work:\n\n\
                   chia://<store id>[:<generation root>]/<path>\n\
                   urn:dig:chia:<store id>[:<generation root>]/<path>\n\n\
                   It opens in your browser, served by your own DIG node.",
            field_label: "DIG link:",
            submit: "Open",
            masked: false,
            revealable: false,
        }) {
            dig_app_core::confirm::InputOutcome::Provided(text) => text,
            dig_app_core::confirm::InputOutcome::Cancelled => return,
            dig_app_core::confirm::InputOutcome::Unavailable => {
                notify(
                    confirmer,
                    "DIG — Open",
                    "DIG could not open an input window on this system.",
                    "This host has no desktop dialog available, so there is nowhere to type the link.",
                );
                return;
            }
        };
        let link = typed.trim();

        // 3. The security boundary, before the link is used for anything.
        if let Err(e) = dig_app_core::gateway::validate_open_link(link) {
            notify(
                confirmer,
                "DIG — Open",
                "That is not a DIG link.",
                &format!(
                    "{}\n\nA DIG link starts with chia:// or urn:dig:chia:",
                    e.message
                ),
            );
            return;
        }

        // 4. Map it onto the node's serve route.
        let url = match dig_app_core::link::serve_url(&endpoint, link) {
            Ok(url) => url,
            Err(reason) => {
                notify(
                    confirmer,
                    "DIG — Open",
                    "That DIG link could not be read.",
                    &format!("{reason}\n\nCheck the link and try again."),
                );
                return;
            }
        };

        // 5. Hand the URL to the browser as a single argument — no shell, ever.
        let opener = if cfg!(target_os = "windows") {
            "explorer"
        } else if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        if std::process::Command::new(opener)
            .arg(&url)
            .spawn()
            .is_err()
        {
            notify(
                confirmer,
                "DIG — Open",
                "DIG could not launch your browser.",
                &format!("The content is here:\n\n{url}"),
            );
        }
    }

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

    /// The DIG brand mark for `glyph`, decoded from the PNG embedded in this binary at the size this
    /// platform's tray paints and badged with the app's state (see [`dig_app::brand`]).
    ///
    /// Returns `None` rather than panicking on any decoding problem: the icon is decoration, and a
    /// user whose agent refused to start because of a bad picture would be far worse served than one
    /// whose tray is briefly unlabelled. The caller mounts the tray either way.
    fn brand_icon(glyph: tray_menu::TrayGlyph) -> Option<Icon> {
        let mark = match dig_app::brand::decode(dig_app::brand::TRAY_MARK) {
            Ok(mark) => dig_app::brand::badged(mark, glyph),
            Err(e) => {
                tracing::warn!(error = %e, "tray icon unavailable — mounting the tray without one");
                return None;
            }
        };
        match Icon::from_rgba(mark.rgba, mark.width, mark.height) {
            Ok(icon) => Some(icon),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    width = mark.width,
                    height = mark.height,
                    "tray rejected the brand mark — mounting the tray without an icon"
                );
                None
            }
        }
    }
}
