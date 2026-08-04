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
    decide_recovery(
        get(ENV_LOG_DIR).is_some_and(|value| !value.trim().is_empty()),
        &dig_logging::resolve_log_dir(service().name, get, |_| true),
        &dig_logging::resolve_log_dir(service().name, get, |_| false),
    )
}

/// The decision behind [`recovery_root`], over the two directories `dig_logging` would resolve.
///
/// Pure and platform-free on purpose. The collapse case is only REACHABLE on Windows — `dev_root` falls
/// back to `%ProgramData%` when `LOCALAPPDATA` is unset, whereas the POSIX roots can never coincide — so an
/// environment-driven test of it is silently vacuous on Linux and macOS. Deciding over the two paths lets
/// the rule be falsified on every host instead of only the one where the environment can express it.
fn decide_recovery(
    overridden: bool,
    machine_dir: &std::path::Path,
    user_dir: &std::path::Path,
) -> Option<std::path::PathBuf> {
    if overridden || user_dir == machine_dir {
        return None;
    }
    user_dir.parent().map(std::path::Path::to_path_buf)
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
    S: Fn(Option<&std::path::Path>),
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

    set(Some(&root));
    match init_once() {
        Ok(guard) => (
            Some(guard),
            vec![format!(
                "the default log directory was unusable ({first}); logging to {} instead",
                root.display()
            )],
        ),
        Err(second) => {
            // Put the override back the way it was found. It named a directory that has now failed
            // too, and the tray's "Open logs" resolves the folder it offers through the very same
            // variable — so leaving it set would point the user's one escape hatch at a directory
            // that does not exist.
            set(None);
            (
                None,
                vec![format!(
                    "could not install structured logging ({first}), and the per-user fallback \
                     {} also failed ({second}); continuing without a log file",
                    root.display()
                )],
            )
        }
    }
}

/// Install the shared logging stack for this process and return the guard. Hold it for the
/// process lifetime (dropping it flushes + detaches the file writer). A failure to install — the
/// log dir is unwritable, or a subscriber is already set — never stops the agent from starting.
///
/// If the directory `dig_logging` resolves on its own is unusable, this retries once against the
/// per-user root (`install` explains why that case is the common one, not the exotic one) and reports
/// the switch through `tracing` — so the recovered log explains its own location instead of leaving the
/// reader to wonder why it moved.
///
/// # Why the total failure is reported TWICE
///
/// When a guard came back, `tracing` is the right channel and the only one that reaches a file. When one
/// did not, **there is no subscriber**, so a `tracing` event on that path is discarded — the exact shape
/// this whole fix exists to remove ("the one message explaining the silence was itself silent"). So the
/// unrecoverable branch ALSO writes to stderr. This binary is GUI-subsystem and usually has no console,
/// which makes stderr a poor channel; it does not make it a worse one than a sink that is provably
/// absent, and a launcher that captures stderr gets the message.
pub fn init() -> Option<LogGuard> {
    let (guard, diagnostics) = install(
        |key| std::env::var(key).ok(),
        |root| match root {
            Some(root) => std::env::set_var(ENV_LOG_DIR, root),
            None => std::env::remove_var(ENV_LOG_DIR),
        },
        || dig_logging::init(service()).map_err(|e| e.to_string()),
    );
    report(
        &diagnostics,
        guard.is_some(),
        |channel, message| match channel {
            Channel::Log => tracing::warn!("{message}"),
            Channel::Stderr => eprintln!("dig-app: WARN {message}"),
        },
    );
    guard
}

/// Where a diagnostic is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Channel {
    /// The `tracing` subscriber — a real file, but ONLY when one was installed.
    Log,
    /// This process's stderr, which a GUI-subsystem run usually does not have.
    Stderr,
}

/// Emit each diagnostic on every channel that can still carry it.
///
/// Split out from [`init`] and given the emitter so the routing is asserted on the messages that ARRIVE,
/// rather than on the fact that a string was built. A test that only counts produced strings passes just
/// as happily when nothing is ever written anywhere, which is the failure this whole module is about.
fn report<E>(diagnostics: &[String], installed: bool, mut emit: E)
where
    E: FnMut(Channel, &str),
{
    // With a logger installed, `tracing` reaches a file and stderr would only duplicate it. Without one
    // there is NO subscriber, so a `tracing` event is discarded — stderr is then the only channel left,
    // poor as it is. It is still emitted on both: `installed` describes dig-app's own guard, and a host
    // that installed its own subscriber first would otherwise lose the message entirely.
    for diagnostic in diagnostics {
        emit(Channel::Log, diagnostic);
        if !installed {
            emit(Channel::Stderr, diagnostic);
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
            |root| *chosen.borrow_mut() = root.map(std::path::Path::to_path_buf),
            || installer(&attempts),
        );

        assert_eq!(guard, Some("guard"), "the retry must produce a live logger");
        assert_eq!(attempts.get(), 2, "the fallback must actually be attempted");
        let chosen = chosen.borrow().clone().expect("a fallback root was chosen");
        assert_eq!(
            Some(chosen.as_path()),
            recovery_root(env(&desktop)).as_deref(),
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
            |root| *chosen.borrow_mut() = root.map(std::path::Path::to_path_buf),
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
            |root| *chosen.borrow_mut() = root.map(std::path::Path::to_path_buf),
            || installer(&attempts),
        );

        assert_eq!(
            guard, None,
            "an operator's unusable choice must not be papered over"
        );
        assert_eq!(attempts.get(), 1);
        assert!(chosen.borrow().is_none());

        // Not `diagnostics.len() == 1`: a produced string that reaches no channel is exactly the
        // silence this module exists to remove, and counting strings cannot tell the two apart.
        assert_eq!(
            emitted(&diagnostics, guard.is_some())
                .into_iter()
                .map(|(channel, message)| (channel, message.contains("attempt 1 denied")))
                .collect::<Vec<_>>(),
            vec![(Channel::Log, true), (Channel::Stderr, true)],
            "an unrecoverable failure must reach BOTH channels, naming the error"
        );
    }

    /// Every message [`report`] actually hands to an emitter, in order.
    fn emitted(diagnostics: &[String], installed: bool) -> Vec<(Channel, String)> {
        let mut seen = Vec::new();
        report(diagnostics, installed, |channel, message| {
            seen.push((channel, message.to_string()))
        });
        seen
    }

    /// With no subscriber installed a `tracing` event is discarded, so stderr is the only channel left
    /// and the diagnostic MUST also go there — the regression guard for "the one message explaining the
    /// silence was itself silent".
    #[test]
    fn a_diagnostic_with_no_logger_installed_still_reaches_stderr() {
        let diagnostics = vec!["nowhere to log".to_string()];

        let channels: Vec<Channel> = emitted(&diagnostics, false)
            .into_iter()
            .map(|(channel, _)| channel)
            .collect();

        assert!(
            channels.contains(&Channel::Stderr),
            "a failure that left no logger must not be reported only to the logger, got {channels:?}"
        );
    }

    /// The converse: once a logger exists it reaches a file, and duplicating every line onto stderr
    /// would be noise. This is what stops the rule above from degenerating into "always print".
    #[test]
    fn a_diagnostic_with_a_working_logger_is_not_duplicated_to_stderr() {
        let diagnostics = vec!["relocated".to_string()];

        assert_eq!(
            emitted(&diagnostics, true),
            vec![(Channel::Log, "relocated".to_string())]
        );
    }

    /// A run with nothing to report writes nothing at all, on either channel.
    #[test]
    fn silence_is_reported_as_silence() {
        assert!(emitted(&[], true).is_empty());
        assert!(emitted(&[], false).is_empty());
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
    ///
    /// Asserted over the two RESOLVED directories rather than through the environment, because the
    /// collapse is only expressible on Windows: `dev_root` falls back to `%ProgramData%` with
    /// `LOCALAPPDATA` unset, while `/var/log/dig` and `~/.local/state/dig/logs` can never coincide. An
    /// env-driven version of this test passes vacuously on Linux and macOS — and did, until CI ran it.
    #[test]
    fn a_collapsed_pair_of_roots_declines_the_retry_rather_than_faking_one() {
        let same = std::path::Path::new("/somewhere/logs/dig-app");

        assert_eq!(
            decide_recovery(false, same, same),
            None,
            "retrying the directory that just failed would be a false recovery"
        );
    }

    #[test]
    fn distinct_roots_recover_into_the_per_user_one() {
        let machine = std::path::Path::new("/machine/logs/dig-app");
        let user = std::path::Path::new("/user/logs/dig-app");

        assert_eq!(
            decide_recovery(false, machine, user),
            Some(std::path::PathBuf::from("/user/logs")),
            "the retry must target the per-user ROOT, which dig_logging re-joins the service onto"
        );
    }

    #[test]
    fn an_override_declines_even_when_the_roots_differ() {
        assert_eq!(
            decide_recovery(
                true,
                std::path::Path::new("/machine/logs/dig-app"),
                std::path::Path::new("/user/logs/dig-app"),
            ),
            None
        );
    }

    /// The `install`-level counterpart, on whichever branch this host can actually express: the retry is
    /// declined, no logger results, and — the part that matters — nothing claims a relocation happened.
    #[test]
    fn a_declined_retry_never_claims_it_relocated() {
        let (attempts, installer) = flaky(1);
        let (guard, diagnostics) = install(
            env(&[(ENV_LOG_DIR, "/operator/choice")]),
            |_| {},
            || installer(&attempts),
        );

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
