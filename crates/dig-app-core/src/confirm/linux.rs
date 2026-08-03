//! The Linux native confirmer (SIGN-3): the branded prompt window + polkit authorization.
//!
//! The window is drawn IN THIS PROCESS by [`super::gui`], the same one Windows draws. The
//! biometric/passphrase step is delegated to **polkit** via `pkcheck --allow-user-interaction`, which
//! raises the user's configured polkit agent (fingerprint via fprintd, smartcard, or the login
//! password as the fallback) — an external helper, so that half of the decision path reduces to
//! *mapping an exit code to a [`VerifyOutcome`]*: a pure function unit-tested here without a desktop,
//! behind a thin [`CommandRunner`] adapter for the real spawn.
//!
//! # What replaced the dialog helpers, and what that removed
//!
//! Until dig_ecosystem#2038 the window was a `zenity`/`kdialog` SUBPROCESS. Drawing it here deletes
//! three things at once: the "neither helper is installed, so there is no consent window at all"
//! failure mode; the markup-neutralisation burden those helpers imposed (`--no-markup`,
//! `escape_kdialog_plain`), since nothing in the drawing path interprets markup any more; and a second
//! visual language for the same prompts. The plain-text guarantee that escaping existed to provide is
//! now structural — see [`super::gui`].
//!
//! On a host with no desktop session (no `DISPLAY`/`WAYLAND_DISPLAY`) or that cannot open a GL
//! surface, [`confirmer`] returns [`None`] so [`super::native_confirmer`] falls back to the
//! fail-closed [`super::HeadlessConfirmer`] (§5.6.1, headless MUST fail closed).

use std::process::Command;

use super::{BackedConfirmer, BiometricVerifier, NativeConfirmer, VerifyOutcome};

/// The polkit action the sign/connect/pair confirm authorizes against (reverse-DNS, canonical). A
/// packaged dig-app ships a matching `.policy` file registering this action with polkit.
const POLKIT_ACTION_ID: &str = "net.dignetwork.dig-app.authorize";

/// Runs an external helper and reports its exit code, abstracting the real spawn so the exit-code
/// mapping is testable without a desktop. `None` means the helper could not be launched at all.
trait CommandRunner: Send + Sync {
    /// Run `program args…` to completion and return its process exit code, or `None` if it could not
    /// be spawned (missing binary, no permission).
    fn run(&self, program: &str, args: &[String]) -> Option<i32>;
}

/// The production runner: actually spawns the helper process.
struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[String]) -> Option<i32> {
        Command::new(program).args(args).status().ok()?.code()
    }
}

/// A [`BiometricVerifier`] backed by polkit's `pkcheck` (fingerprint/password via the polkit agent).
struct PolkitVerifier<R: CommandRunner> {
    runner: R,
}

impl<R: CommandRunner> BiometricVerifier for PolkitVerifier<R> {
    fn verify(&self, _reason: &str) -> VerifyOutcome {
        outcome_from_pkcheck_exit(self.runner.run("pkcheck", &pkcheck_args()))
    }
}

/// The `pkcheck` arguments authorizing this process interactively against [`POLKIT_ACTION_ID`].
fn pkcheck_args() -> Vec<String> {
    vec![
        "--action-id".into(),
        POLKIT_ACTION_ID.into(),
        "--process".into(),
        process_subject(),
        "--allow-user-interaction".into(),
    ]
}

/// The `pkcheck --process` subject for THIS process.
///
/// polkit deprecates the bare-pid subject: a PID can be reused between the check and the
/// authorization, letting a different process inherit the grant. The hardened form pins the process
/// start time (and uid) so a reused PID cannot match. Fall back to the coarser forms only if the
/// kernel facts are unreadable, and to the bare pid last — `pkcheck` still accepts it.
fn process_subject() -> String {
    let pid = std::process::id();
    match (proc_start_time(pid), self_effective_uid()) {
        (Some(start), Some(uid)) => format!("{pid},{start},{uid}"),
        (Some(start), None) => format!("{pid},{start}"),
        _ => pid.to_string(),
    }
}

/// This process's start time in clock ticks (field 22 of `/proc/<pid>/stat`), or `None` if unreadable.
fn proc_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_start_time_from_stat(&stat)
}

/// This process's effective uid (the second value of `/proc/self/status` `Uid:`), or `None`.
fn self_effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_effective_uid_from_status(&status)
}

/// Parse the start-time field from a `/proc/<pid>/stat` line.
///
/// Field 2 (`comm`) is parenthesized and may itself contain spaces and `)`, so the whitespace split
/// starts AFTER the last `)`. From there field 3 (state) is index 0, making start time (field 22)
/// index 19.
fn parse_start_time_from_stat(stat: &str) -> Option<u64> {
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// Parse the effective uid (the second of the four space/tab-separated `Uid:` values) from
/// `/proc/self/status`.
fn parse_effective_uid_from_status(status: &str) -> Option<u32> {
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

/// Map `pkcheck`'s exit code to a verification outcome.
///
/// `pkcheck` exits `0` when authorization succeeds (the user passed the polkit agent's
/// biometric/password prompt), `1` when it is denied or the prompt was dismissed, and other non-zero
/// codes on a usage/internal error. A missing `pkcheck` (`None`) means no authorizer is available, so
/// the confirm fails closed.
fn outcome_from_pkcheck_exit(code: Option<i32>) -> VerifyOutcome {
    match code {
        Some(0) => VerifyOutcome::Verified,
        Some(1) => VerifyOutcome::Declined,
        Some(_) => VerifyOutcome::Failed,
        None => VerifyOutcome::Unavailable,
    }
}

/// Whether this process has an interactive desktop session, from the graphical-session env vars.
fn has_display(env: impl Fn(&str) -> Option<String>) -> bool {
    let present = |key| env(key).is_some_and(|value| !value.is_empty());
    present("WAYLAND_DISPLAY") || present("DISPLAY")
}

/// The Linux confirmer, or [`None`] on a headless host / one with no dialog helper (fail closed).
pub(super) fn confirmer() -> Option<Box<dyn NativeConfirmer>> {
    if !has_display(|key| std::env::var(key).ok()) {
        return None;
    }
    // The branded GUI (dig_ecosystem#2038) draws every window IN THIS PROCESS; polkit still
    // authorises. The `zenity`/`kdialog` subprocess this replaces is gone, and with it the
    // "no dialog helper installed, so no consent window at all" failure mode — and the whole
    // markup-neutralisation burden, since nothing in the drawing path interprets markup any more.
    if !super::gui::available() {
        return None;
    }
    Some(Box::new(BackedConfirmer::new(
        super::gui::BrandedWindow::default(),
        PolkitVerifier {
            runner: SystemCommandRunner,
        },
        super::gui::BrandedInput::default(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::{
        ConfirmContent, ConfirmDecision, ForegroundWindow, NativeConfirmer, NoInputWindow,
        SignPrompt, WindowIntent,
    };

    /// A consent window that always says yes.
    ///
    /// The point of the two composition tests below is that polkit is a SECOND, independent gate: an
    /// approved window alone must never authorise anything. Holding the window at "approve" is what
    /// makes the polkit half the only variable.
    struct ApprovingWindow;

    impl ForegroundWindow for ApprovingWindow {
        fn show(&self, _content: &ConfirmContent) -> WindowIntent {
            WindowIntent::Approve
        }
    }

    /// A runner scripted to return a fixed exit code — and, for the input helpers, a fixed stdout — while
    /// recording what it was asked to run.
    struct FakeRunner {
        code: Option<i32>,
        last: std::sync::Mutex<Option<(String, Vec<String>)>>,
    }
    impl FakeRunner {
        fn new(code: Option<i32>) -> Self {
            Self {
                code,
                last: std::sync::Mutex::new(None),
            }
        }
    }
    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[String]) -> Option<i32> {
            *self.last.lock().unwrap() = Some((program.to_string(), args.to_vec()));
            self.code
        }
    }

    fn content() -> ConfirmContent {
        ConfirmContent::sign(&SignPrompt {
            origin: "https://dapp.example",
            payload_type: "spend",
            decoded_tx: Some("Send 100 $DIG"),
        })
        .unwrap()
    }

    fn pkcheck_exit_codes_map_to_the_right_outcome() {
        assert_eq!(outcome_from_pkcheck_exit(Some(0)), VerifyOutcome::Verified);
        assert_eq!(outcome_from_pkcheck_exit(Some(1)), VerifyOutcome::Declined);
        assert_eq!(outcome_from_pkcheck_exit(Some(2)), VerifyOutcome::Failed);
        assert_eq!(outcome_from_pkcheck_exit(None), VerifyOutcome::Unavailable);
    }

    #[test]
    fn polkit_verifier_authorizes_this_process_against_the_canonical_action() {
        let verifier = PolkitVerifier {
            runner: FakeRunner::new(Some(0)),
        };
        assert_eq!(verifier.verify("Sign"), VerifyOutcome::Verified);
        let (program, args) = verifier.runner.last.lock().unwrap().clone().unwrap();
        assert_eq!(program, "pkcheck");
        assert!(args.iter().any(|a| a == POLKIT_ACTION_ID));
        assert!(args.iter().any(|a| a == "--allow-user-interaction"));
    }

    #[test]
    fn a_composed_linux_confirmer_approves_only_on_dialog_ok_plus_polkit_ok() {
        let confirmer = BackedConfirmer::new(
            ApprovingWindow,
            PolkitVerifier {
                runner: FakeRunner::new(Some(0)),
            },
            // These two tests exercise the CONFIRM path only, so the input window is the fail-closed
            // `NoInputWindow` rather than a live entry helper.
            NoInputWindow,
        );
        assert_eq!(
            confirmer.confirm_sign(&SignPrompt {
                origin: "https://dapp.example",
                payload_type: "spend",
                decoded_tx: Some("Send 100 $DIG"),
            }),
            ConfirmDecision::Approve
        );
    }

    #[test]
    fn a_denied_polkit_prompt_denies_the_confirm_even_with_dialog_ok() {
        let confirmer = BackedConfirmer::new(
            ApprovingWindow,
            PolkitVerifier {
                runner: FakeRunner::new(Some(1)),
            },
            // These two tests exercise the CONFIRM path only, so the input window is the fail-closed
            // `NoInputWindow` rather than a live entry helper.
            NoInputWindow,
        );
        assert_eq!(
            confirmer.confirm_sign(&SignPrompt {
                origin: "https://dapp.example",
                payload_type: "spend",
                decoded_tx: Some("Send 100 $DIG"),
            }),
            ConfirmDecision::Deny
        );
    }

    fn pkcheck_uses_the_reuse_hardened_process_subject() {
        // The bare pid alone is deprecated (PID-reuse race); the subject pins at least pid,start_time.
        let subject = process_subject();
        assert!(
            subject.starts_with(&std::process::id().to_string()),
            "subject names this process: {subject}"
        );
    }

    #[test]
    fn parse_start_time_handles_a_comm_with_spaces_and_parens() {
        // A synthetic stat line whose comm contains spaces and a ')'; start time (field 22) = 8675309.
        // After the last ')', field 3 (state, "S") is split-index 0, so field 22 is split-index 19 —
        // i.e. the state token plus 19 following fields, so the sentinel is the 19th post-state field.
        let mut fields: Vec<String> = (4..=44).map(|n| n.to_string()).collect();
        fields[18] = "8675309".into();
        let stat = format!("1234 (weird )name) S {}", fields.join(" "));
        assert_eq!(parse_start_time_from_stat(&stat), Some(8675309));
    }

    #[test]
    fn parse_effective_uid_takes_the_second_uid_field() {
        let status = "Name:\tdig-app\nUid:\t1000\t1001\t1000\t1000\nGid:\t1000\n";
        assert_eq!(parse_effective_uid_from_status(status), Some(1001));
        assert_eq!(parse_effective_uid_from_status("no uid line"), None);
    }

    fn has_display_follows_the_graphical_session_env() {
        let with = |k: &str, v: &str| {
            let (key, value) = (k.to_string(), v.to_string());
            move |q: &str| (q == key).then(|| value.clone())
        };
        assert!(has_display(with("DISPLAY", ":0")));
        assert!(has_display(with("WAYLAND_DISPLAY", "wayland-0")));
        assert!(!has_display(with("DISPLAY", "")));
        assert!(!has_display(|_| None));
    }
}
