//! `dign` — the DIG user CLI (owned by dig-app).
//!
//! Thin entrypoint: `dign` talks to the running user app over the identity-authenticated IPC
//! ([`dig_app_core::ipc`]), which authenticates the caller and proxies engine work. The user/
//! identity subcommands migrate here from dig-node; `dig-node` keeps only machine service-lifecycle.
//! U7 implements the gateway + command surface. This binary is intentionally minimal.

fn main() {
    // U7: parse the invocation and dispatch through dig_app_core::gateway to the user app session.
    eprintln!(
        "dign {} — the DIG user CLI. Command surface lands in U7 (epic #908).",
        env!("CARGO_PKG_VERSION")
    );
}
