//! Structured logging for the `dig-app` shell binary (#934), built on the shared [`dig_logging`]
//! building block (#547) — the same one `dig-node`/`dig-dns`/`dig-updater` use, so a bug-report
//! bundle looks identical across every DIG binary.
//!
//! Before this module the agent core ([`dig_app_core`]) emitted `tracing` events into the void: no
//! subscriber was ever installed, so a tray-shell run left no trace of what the identity agent did
//! all session. [`init`] installs the shared dual sink — a rolling daily JSONL file in the per-OS
//! machine log dir plus compact human text on stderr — behind one reloadable level filter.
//!
//! ## One process-wide guard
//!
//! `tracing` has exactly one global subscriber per process. `dig-app` has exactly one entrypoint
//! ([`main`](crate) in `src/bin/dig-app.rs`), so — unlike `dig-node-service`, which installs from
//! several possible serve paths — a plain local guard held for the duration of `main` is enough;
//! there is no second caller [`init`] needs to be idempotent against.

use dig_logging::{LogGuard, RunContext, Service};

/// The service identity every `dig-logging` call for this binary uses. `dig-app` runs as a
/// long-lived per-user background agent (tray or headless), so it always logs under
/// [`RunContext::Service`] — the machine log dir, matching how an installed OS-service run is
/// distinguished from a one-shot CLI invocation ([`crate::logging`] vs. `dign`'s own init).
pub fn service() -> Service {
    Service {
        name: "dig-app",
        version: env!("CARGO_PKG_VERSION"),
        run_context: RunContext::Service,
    }
}

/// Where this binary's log files live, resolved the same way [`init`] resolves them.
///
/// Exposed so the tray can OPEN the folder for the user: "read the logs" is the escape hatch every
/// unexplainable failure points at (§6.1), and a path a person has to work out for themselves is not an
/// escape hatch. Resolving it through `dig_logging` rather than re-deriving a per-OS path is what keeps
/// the folder the tray opens the folder the logs are actually in.
pub fn log_dir() -> std::path::PathBuf {
    dig_logging::log_dir(service().name)
}

/// Install the shared logging stack for this process and return the guard. Hold it for the
/// process lifetime (dropping it flushes + detaches the file writer). A failure to install — the
/// log dir is unwritable, or a subscriber is already set — is reported on stderr and swallowed:
/// a logging problem must NEVER stop the agent from starting.
pub fn init() -> Option<LogGuard> {
    match dig_logging::init(service()) {
        Ok(guard) => Some(guard),
        Err(e) => {
            eprintln!(
                "dig-app: WARN could not install structured logging ({e}); continuing without a log file"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_identity_names_the_binary_and_runs_as_a_service() {
        let svc = service();
        assert_eq!(svc.name, "dig-app");
        assert_eq!(svc.run_context, RunContext::Service);
        assert_eq!(svc.version, env!("CARGO_PKG_VERSION"));
    }
}
