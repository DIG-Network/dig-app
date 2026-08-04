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

/// The env var whose value `dig_logging` treats as the log ROOT, overriding its own resolution.
const ENV_LOG_DIR: &str = "DIG_LOG_DIR";

/// The per-user log root — the directory `dig_logging` itself falls back to for an unprivileged run.
///
/// Derived by asking `dig_logging` to resolve with a probe that refuses the machine root, rather than
/// re-deriving `%LOCALAPPDATA%\DigNetwork\logs` and its two POSIX equivalents here. A second copy of a
/// per-OS path is a future drift bug, and this way dig-app's recovery lands in exactly the directory the
/// shared crate would have chosen on its own.
fn user_log_root<G>(get: G) -> Option<std::path::PathBuf>
where
    G: Fn(&str) -> Option<String>,
{
    let service_dir = dig_logging::resolve_log_dir(service().name, get, |_| false);
    service_dir.parent().map(std::path::Path::to_path_buf)
}

/// Where to retry after `dig_logging::init` fails, or `None` when a retry would be wrong.
///
/// Two cases decline the retry:
///
/// * **An operator set `DIG_LOG_DIR`.** They have NAMED the directory they want logs in. If it is
///   unusable, quietly writing somewhere else hides their misconfiguration in the one place they will
///   not look. The retry exists only for the resolution dig-app made on its own behalf.
/// * **The per-user root is the machine root.** `dig_logging`'s Windows per-user root falls back to
///   `%ProgramData%` when `LOCALAPPDATA` is unset, so on a stripped environment (a service account, a
///   scrubbed scheduled task) both branches name the same directory. Retrying there would re-attempt the
///   very directory that just failed and report a relocation that did not happen — a false recovery is
///   worse than an honest failure.
fn recovery_root<G>(get: G) -> Option<std::path::PathBuf>
where
    G: Fn(&str) -> Option<String> + Copy,
{
    let overridden = get(ENV_LOG_DIR).is_some_and(|value| !value.trim().is_empty());
    if overridden {
        return None;
    }
    let machine_dir = dig_logging::resolve_log_dir(service().name, get, |_| true);
    let user_dir = dig_logging::resolve_log_dir(service().name, get, |_| false);
    if user_dir == machine_dir {
        return None;
    }
    user_log_root(get)
}

/// Install the logging stack, retrying once against the per-user root, and return the guard plus any
/// diagnostics the caller should emit ONCE a subscriber exists.
///
/// Generic over the installer and the environment so every branch is exercised without touching the real
/// filesystem, environment, or the process-global `tracing` subscriber — which one test would consume for
/// the whole binary.
///
/// The retry is what this function exists for (dig_ecosystem#2074). `dig_logging` decides between the
/// machine log root and a per-user fallback with the probe `create_dir_all(path).is_ok()`, and
/// `create_dir_all` answers `Ok` for a directory that ALREADY EXISTS whatever its ACL. On Windows the
/// machine root is created by an elevated run and then DACL'd `{SYSTEM, Administrators}` full control by
/// dig-installer #715, with `BUILTIN\Users` granted read+execute — never write — by #728. So for an
/// ordinary login-launched dig-app the probe reports a directory it can never write, the per-user
/// fallback is skipped, and the appender fails on its first file open. Retrying under an explicit
/// `DIG_LOG_DIR` is how dig-app reaches the fallback the shared crate could not.
fn install<G, S, I, T>(get: G, set: S, mut init_once: I) -> (Option<T>, Vec<String>)
where
    G: Fn(&str) -> Option<String> + Copy,
    S: Fn(&std::path::Path),
    I: FnMut() -> std::result::Result<T, String>,
{
    let first = match init_once() {
        Ok(guard) => return (Some(guard), Vec::new()),
        Err(e) => e,
    };

    let Some(root) = recovery_root(get) else {
        return (
            None,
            vec![format!(
                "could not install structured logging ({first}); continuing without a log file"
            )],
        );
    };

    set(&root);
    match init_once() {
        Ok(guard) => (
            Some(guard),
            vec![format!(
                "the default log directory was unusable ({first}); logging to {} instead",
                root.display()
            )],
        ),
        Err(second) => (
            None,
            vec![format!(
                "could not install structured logging ({first}), and the per-user fallback \
                 {} also failed ({second}); continuing without a log file",
                root.display()
            )],
        ),
    }
}

/// Install the shared logging stack for this process and return the guard. Hold it for the
/// process lifetime (dropping it flushes + detaches the file writer). A failure to install — the
/// log dir is unwritable, or a subscriber is already set — never stops the agent from starting.
///
/// If the directory `dig_logging` resolves on its own is unusable, this retries once against the
/// per-user root ([`install`] explains why that case is the common one, not the exotic one) and reports
/// the switch through `tracing` — so the recovered log explains its own location instead of leaving the
/// reader to wonder why it moved. Reporting through `tracing` rather than `eprintln!` is deliberate:
/// this binary is GUI-subsystem and has no console, so anything written to stderr is written to nowhere.
pub fn init() -> Option<LogGuard> {
    let (guard, diagnostics) = install(
        |key| std::env::var(key).ok(),
        |root| std::env::set_var(ENV_LOG_DIR, root),
        || dig_logging::init(service()).map_err(|e| e.to_string()),
    );
    for diagnostic in diagnostics {
        tracing::warn!("{diagnostic}");
    }
    guard
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

    /// An environment getter over a fixed map, so a test names exactly the vars it sets.
    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + Copy + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| (*v).to_string())
        }
    }

    /// The per-OS vars that give `dig_logging` a per-user root distinct from the machine root — an
    /// ordinary logged-in desktop, which is the environment this bug happens in.
    fn desktop() -> Vec<(&'static str, &'static str)> {
        #[cfg(windows)]
        {
            vec![("LOCALAPPDATA", r"C:\Users\tester\AppData\Local")]
        }
        #[cfg(not(windows))]
        {
            vec![
                ("HOME", "/home/tester"),
                ("XDG_STATE_HOME", "/home/tester/.state"),
            ]
        }
    }

    /// An installer that fails `failures` times and then succeeds, counting every attempt.
    fn flaky(
        failures: usize,
    ) -> (
        std::cell::Cell<usize>,
        impl Fn(&std::cell::Cell<usize>) -> Result<&'static str, String>,
    ) {
        (
            std::cell::Cell::new(0),
            move |attempts: &std::cell::Cell<usize>| {
                attempts.set(attempts.get() + 1);
                if attempts.get() <= failures {
                    Err(format!("attempt {} denied", attempts.get()))
                } else {
                    Ok("guard")
                }
            },
        )
    }

    /// The regression test for dig_ecosystem#2074: the machine log root exists but is unwritable, so
    /// `dig_logging` picks it, its appender fails, and dig-app used to give up — leaving a GUI-subsystem
    /// process with no log at all and no way to say so. It must now retry against the per-user root.
    #[test]
    fn an_unwritable_default_log_dir_is_retried_against_the_per_user_root() {
        let (attempts, installer) = flaky(1);
        let chosen = std::cell::RefCell::new(None);

        let desktop = desktop();
        let (guard, diagnostics) = install(
            env(&desktop),
            |root| *chosen.borrow_mut() = Some(root.to_path_buf()),
            || installer(&attempts),
        );

        assert_eq!(guard, Some("guard"), "the retry must produce a live logger");
        assert_eq!(attempts.get(), 2, "the fallback must actually be attempted");
        let chosen = chosen.borrow().clone().expect("a fallback root was chosen");
        assert_eq!(
            Some(chosen.as_path()),
            user_log_root(env(&desktop)).as_deref(),
            "the retry must land in the per-user root dig_logging itself falls back to"
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.contains(&chosen.display().to_string())),
            "a relocated log must name its own new location, got {diagnostics:?}"
        );
    }

    #[test]
    fn a_working_default_log_dir_is_left_alone() {
        let (attempts, installer) = flaky(0);
        let chosen = std::cell::RefCell::new(None);

        let (guard, diagnostics) = install(
            env(&desktop()),
            |root| *chosen.borrow_mut() = Some(root.to_path_buf()),
            || installer(&attempts),
        );

        assert_eq!(guard, Some("guard"));
        assert_eq!(attempts.get(), 1, "a healthy install must not be retried");
        assert!(chosen.borrow().is_none(), "nothing may be overridden");
        assert!(diagnostics.is_empty(), "silence is correct when it worked");
    }

    #[test]
    fn an_operator_chosen_log_dir_is_never_second_guessed() {
        let (attempts, installer) = flaky(1);
        let chosen = std::cell::RefCell::new(None);

        let (guard, diagnostics) = install(
            env(&[(ENV_LOG_DIR, "/operator/choice")]),
            |root| *chosen.borrow_mut() = Some(root.to_path_buf()),
            || installer(&attempts),
        );

        assert_eq!(
            guard, None,
            "an operator's unusable choice must not be papered over"
        );
        assert_eq!(attempts.get(), 1);
        assert!(chosen.borrow().is_none());
        assert_eq!(diagnostics.len(), 1, "the failure must still be reported");
    }

    #[test]
    fn a_blank_override_does_not_disable_the_retry() {
        let (attempts, installer) = flaky(1);
        let (guard, _) = install(
            env(&[(ENV_LOG_DIR, "   ")]
                .iter()
                .chain(desktop().iter())
                .copied()
                .collect::<Vec<_>>()),
            |_| {},
            || installer(&attempts),
        );

        assert_eq!(guard, Some("guard"), "a blank var is unset, not a choice");
        assert_eq!(attempts.get(), 2);
    }

    #[test]
    fn the_retry_is_attempted_at_most_once() {
        let (attempts, installer) = flaky(usize::MAX);
        let (guard, diagnostics) = install(env(&desktop()), |_| {}, || installer(&attempts));

        assert_eq!(guard, None);
        assert_eq!(attempts.get(), 2, "a doomed install must not loop");
        assert_eq!(diagnostics.len(), 1);
        assert!(
            diagnostics[0].contains("attempt 1 denied")
                && diagnostics[0].contains("attempt 2 denied"),
            "both failures must be named, got {diagnostics:?}"
        );
    }

    #[test]
    fn the_recovery_root_is_never_the_directory_that_just_failed() {
        let desktop = desktop();
        let recovery = recovery_root(env(&desktop)).expect("a desktop has a per-user root");
        let machine = dig_logging::resolve_log_dir(service().name, env(&desktop), |_| true);
        assert!(
            !machine.starts_with(&recovery),
            "retrying inside the unwritable machine root would be a false recovery: {} vs {}",
            recovery.display(),
            machine.display()
        );
    }

    /// A stripped environment (a service account, a scrubbed scheduled task) collapses dig_logging's
    /// per-user Windows root onto `%ProgramData%` — the very root that was unwritable. Retrying there
    /// would report a relocation that never happened, so the retry must be declined outright.
    #[test]
    fn a_degenerate_environment_declines_the_retry_rather_than_faking_one() {
        let (attempts, installer) = flaky(1);
        let (guard, diagnostics) = install(env(&[]), |_| {}, || installer(&attempts));

        assert_eq!(guard, None, "no logger is honest; a fake relocation is not");
        assert_eq!(
            attempts.get(),
            1,
            "the same failed directory must not be retried"
        );
        assert_eq!(diagnostics.len(), 1);
        assert!(
            !diagnostics[0].contains("instead"),
            "nothing was relocated, so nothing may claim it was: {}",
            diagnostics[0]
        );
    }
}
