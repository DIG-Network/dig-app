//! `dig-app` — the branded per-user identity-agent shell.
//!
//! Thin entrypoint: it mounts the tray / menu-bar shell over the [`dig_app_core`] agent core when a
//! desktop session is present, and degrades to a headless agent on a GUI-less host. All logic lives
//! in `dig-app-core` (so it is unit-tested there); U3 implements the shell + the headless agent
//! runtime. This binary is intentionally minimal.

fn main() {
    // U3: detect the form factor (dig_app_core::form_factor::FormFactor::detect), then either mount
    // the tray shell or run headless as the per-user identity agent.
    eprintln!(
        "dig-app {} — the DIG user app (identity agent). Agent runtime lands in U3 (epic #908).",
        env!("CARGO_PKG_VERSION")
    );
}
