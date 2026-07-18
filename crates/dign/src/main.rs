//! `dign` — the DIG user CLI (epic dig_ecosystem#908, U7).
//!
//! Thin process edge over [`dig_app_core::gateway`]: `dign` parses the invocation, hands it to the
//! gateway, and renders the result. The gateway routes each command — LOCAL (served with the held
//! user identity: sign / profiles / wallet) or PROXY (forwarded over the identity-authenticated
//! session to the engine). The full command surface + routing lands in U7.

fn main() {
    // U7: parse the invocation and dispatch through `dig_app_core::gateway`.
    eprintln!(
        "dign {} — the DIG user CLI. Command surface + gateway routing land in U7 (epic #908).",
        env!("CARGO_PKG_VERSION")
    );
}
