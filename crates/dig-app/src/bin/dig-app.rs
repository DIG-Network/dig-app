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
use dig_app_core::engine::NullConnector;
use dig_app_core::environment::AppEnvironment;
use dig_app_core::form_factor::FormFactor;
use dig_app_core::Os;

fn main() {
    let version = env!("CARGO_PKG_VERSION");
    let env = resolve_environment();

    let agent = match Agent::from_env(&env, NullConnector) {
        Ok(agent) => agent,
        Err(e) => {
            eprintln!("dig-app {version}: cannot start — {e}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "dig-app {version} — user identity agent starting (endpoint: {})",
        agent.endpoint()
    );

    match env.form_factor() {
        FormFactor::Tray => run_tray_or_headless(agent),
        FormFactor::Headless => {
            eprintln!("dig-app: no desktop display — running as headless agent (no tray)");
            agent.run();
        }
    }
}

/// Mount the tray shell, degrading to the headless agent if the tray cannot be built (no display,
/// no desktop stack) or if the `tray` feature is disabled at build time.
fn run_tray_or_headless(agent: Agent<NullConnector>) {
    #[cfg(feature = "tray")]
    match tray::run(agent) {
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
        eprintln!("dig-app: built without the tray feature — running as headless agent");
        agent.run();
    }
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
    pub fn run(agent: Agent<NullConnector>) -> Result<(), (String, Agent<NullConnector>)> {
        let event_loop = EventLoopBuilder::new().build();

        let menu = Menu::new();
        let running_item = MenuItem::new("DIG — starting…", false, None);
        let engine_item = MenuItem::new("Engine: connecting…", false, None);
        let profile_item = MenuItem::new("Profile: (none)", false, None);
        let quit_item = MenuItem::new("Quit DIG", true, None);
        if let Err(e) = menu.append_items(&[
            &running_item,
            &engine_item,
            &profile_item,
            &PredefinedMenuItem::separator(),
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
        let menu_events = MenuEvent::receiver();

        // The event loop diverges; `_tray` stays alive on this frame for the whole process.
        event_loop.run(move |_event, _target, control_flow| {
            *control_flow = ControlFlow::WaitUntil(Instant::now() + REFRESH);
            repaint(&status, &running_item, &engine_item, &profile_item);

            while let Ok(event) = menu_events.try_recv() {
                if event.id == quit_id {
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
