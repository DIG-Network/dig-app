//! `dign` — the DIG user CLI (epic dig_ecosystem#908, U7).
//!
//! `dign` is a thin IPC CLIENT of the running dig-app (SPEC §3.5): it parses the invocation into a
//! gateway [`Command`], sends it to the user app over the identity-authenticated per-user channel,
//! and renders the [`Outcome`] the app's gateway returns — pretty on stderr by default, or one JSON
//! object on stdout under `--json`. The app (not `dign`) decides whether the command is served
//! locally with the user identity or proxied to the engine.
//!
//! The per-user IPC session client is owned by the dig-app IPC layer (APP-1 / U6). Until it lands,
//! [`send_to_app`] reports a clean `NOT_CONNECTED` error, so `dign` already offers its full parsed
//! command surface + `--help`/`--json` discovery and drops onto the real session with a one-line
//! swap.

mod cli;

use clap::Parser;
use dig_app_core::gateway::{
    error_envelope, success_envelope, Command, ErrorCode, GatewayError, Outcome,
};
use dig_logging::{RunContext, Service};

use cli::Cli;

fn main() {
    // `dign` is a short-lived, one-shot invocation, so the guard is a plain local — held for this
    // single run and dropped (flushing the writer) when `main` returns. `RunContext::Cli` resolves
    // the SAME per-user log directory `dig-app`'s `RunContext::Service` writes to (SPEC §3 of
    // `dig-logging`), so `dign logs tail` — once wired — would show both processes interleaved.
    let _log_guard = dig_logging::init(Service {
        name: "dig-app",
        version: env!("CARGO_PKG_VERSION"),
        run_context: RunContext::Cli,
    });

    let cli = Cli::parse();
    let command = cli.command.into_command();
    let action = command.action();
    tracing::debug!(action, "dispatching command");

    let exit = match send_to_app(&command) {
        Ok(outcome) => render_success(action, &outcome, cli.json),
        Err(error) => render_error(action, &error, cli.json),
    };
    std::process::exit(exit as i32);
}

/// Send `command` to the running dig-app over the identity-authenticated session and return its
/// [`Outcome`].
///
/// The concrete IPC client lands with APP-1 (U6); until then this reports `NOT_CONNECTED` so the
/// failure is catalogued and scriptable rather than a panic. At integration this becomes the real
/// per-user channel round-trip — the gateway itself already lives in `dig-app-core`.
fn send_to_app(_command: &Command) -> Result<Outcome, GatewayError> {
    Err(GatewayError::new(
        ErrorCode::NotConnected,
        "the dig-app session is not available yet",
    )
    .with_hint("the per-user IPC session to dig-app lands with APP-1 (U6)"))
}

/// Render a successful outcome and return the process exit code (always `OK`).
///
/// Only the ACTION name is logged, never `outcome.result` — a local/wallet command's result can
/// carry a signature or an address, and while neither is private key material, the log line stays a
/// deliberately narrow surface (the never-log discipline is "don't reach into arbitrary payloads",
/// not "trust every field is safe").
fn render_success(action: &str, outcome: &Outcome, json: bool) -> u8 {
    tracing::info!(action, "command succeeded");
    if json {
        println!("{}", success_envelope(action, &outcome.result));
    } else {
        eprintln!("{}", outcome.summary);
    }
    ErrorCode::Ok.code()
}

/// Render a failure and return its catalogued process exit code.
fn render_error(action: &str, error: &GatewayError, json: bool) -> u8 {
    tracing::warn!(action, code = ?error.code, message = %error.message, "command failed");
    if json {
        println!("{}", error_envelope(action, error));
    } else {
        eprintln!("dign: {}", error.message);
        if let Some(hint) = &error.hint {
            eprintln!("hint: {hint}");
        }
    }
    error.code.code()
}
