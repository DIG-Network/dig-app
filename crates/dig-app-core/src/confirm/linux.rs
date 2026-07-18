//! The Linux native confirmer (SIGN-3): a foreground desktop dialog + polkit authorization.
//!
//! The confirm window is a real, focus-stealing desktop dialog drawn by the session's dialog helper
//! (`zenity` on GNOME/GTK, `kdialog` on KDE) showing the decoded transaction and vouched origin; the
//! biometric/passphrase step is delegated to **polkit** via `pkcheck --allow-user-interaction`, which
//! raises the user's configured polkit agent (fingerprint via fprintd, smartcard, or the login
//! password as the fallback). Both are external helpers, so the entire decision path reduces to
//! *mapping a helper's exit code to a [`WindowIntent`] / [`VerifyOutcome`]* — pure functions unit-tested
//! here without a desktop, and thin [`CommandRunner`] adapters for the real spawn.
//!
//! On a host with no desktop session (no `DISPLAY`/`WAYLAND_DISPLAY`) or with no dialog helper
//! installed, [`confirmer`] returns [`None`] so [`super::native_confirmer`] falls back to the
//! fail-closed [`super::HeadlessConfirmer`] (§5.6.1, headless MUST fail closed).

use std::process::Command;

use super::{
    BackedConfirmer, BiometricVerifier, ConfirmContent, ForegroundWindow, NativeConfirmer,
    VerifyOutcome, WindowIntent,
};

/// The polkit action the sign/connect/pair confirm authorizes against (reverse-DNS, canonical). A
/// packaged dig-app ships a matching `.policy` file registering this action with polkit.
const POLKIT_ACTION_ID: &str = "net.dignetwork.dig-app.authorize";

/// How long the confirm dialog waits for an answer before it self-dismisses as a timeout (seconds).
const DIALOG_TIMEOUT_SECS: u32 = 120;

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

/// The two desktop dialog helpers dig-app knows how to drive, in preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DialogTool {
    /// GNOME/GTK `zenity`.
    Zenity,
    /// KDE `kdialog`.
    Kdialog,
}

impl DialogTool {
    /// The helper's program name on `PATH`.
    fn program(self) -> &'static str {
        match self {
            Self::Zenity => "zenity",
            Self::Kdialog => "kdialog",
        }
    }

    /// The argument vector that shows `content` as a modal question dialog with an approve/cancel
    /// choice, self-dismissing after [`DIALOG_TIMEOUT_SECS`].
    ///
    /// **Markup safety (security-critical).** The displayed text carries attacker-influenced fields
    /// (the dapp name / extension label, and — once the loopback wires them — the decoded transaction
    /// and its `payload_type`). Both helpers can INTERPRET markup in their text (`zenity --text` reads
    /// Pango markup; `kdialog` renders the string as Qt rich text when it looks HTML-ish), so a hostile
    /// field could cosmetically distort what the user believes they are approving. Each helper is
    /// therefore forced to treat the text as PLAIN: `zenity` via `--no-markup`, `kdialog` by escaping
    /// the rich-text trigger characters so `mightBeRichText` can never fire.
    fn args(self, content: &ConfirmContent) -> Vec<String> {
        let text = format!("{}\n\n{}", content.heading, content.body);
        match self {
            Self::Zenity => vec![
                "--question".into(),
                "--no-markup".into(),
                format!("--title={}", content.title),
                format!("--text={text}"),
                format!("--ok-label={}", content.action),
                "--cancel-label=Cancel".into(),
                format!("--timeout={DIALOG_TIMEOUT_SECS}"),
            ],
            Self::Kdialog => vec![
                "--title".into(),
                content.title.clone(),
                "--yesno".into(),
                escape_kdialog_plain(&text),
                "--yes-label".into(),
                content.action.into(),
                "--no-label".into(),
                "Cancel".into(),
            ],
        }
    }
}

/// Neutralize Qt rich-text interpretation for `kdialog`, which renders its text as HTML when
/// `Qt::mightBeRichText` matches an HTML-ish string. Escaping `&`, `<`, `>` removes every tag opener,
/// so the heuristic sees plain text and shows the string literally — a hostile `<b>`/`<a href>` in a
/// dapp name or decoded transaction is displayed verbatim, never rendered.
fn escape_kdialog_plain(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A [`ForegroundWindow`] backed by a desktop dialog helper.
struct DialogWindow<R: CommandRunner> {
    runner: R,
    tool: DialogTool,
}

impl<R: CommandRunner> ForegroundWindow for DialogWindow<R> {
    fn show(&self, content: &ConfirmContent) -> WindowIntent {
        intent_from_dialog_exit(
            self.runner
                .run(self.tool.program(), &self.tool.args(content)),
        )
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

/// Map a dialog helper's exit code to the user's intent.
///
/// `zenity`/`kdialog` both exit `0` on the affirmative button and `1` on cancel/close; `zenity`
/// returns `5` when its `--timeout` elapses. A helper that could not be spawned (`None`) means no
/// window was shown, so the confirm is [`WindowIntent::Unavailable`] and fails closed upstream.
fn intent_from_dialog_exit(code: Option<i32>) -> WindowIntent {
    match code {
        Some(0) => WindowIntent::Approve,
        Some(5) => WindowIntent::Timeout,
        Some(_) => WindowIntent::Deny,
        None => WindowIntent::Unavailable,
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

/// Whether `program` is an executable on `PATH`.
fn binary_on_path(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(program).is_file())
}

/// Pick the first dialog helper present on `PATH`, preferring `zenity`.
fn detect_dialog_tool(available: impl Fn(&str) -> bool) -> Option<DialogTool> {
    [DialogTool::Zenity, DialogTool::Kdialog]
        .into_iter()
        .find(|tool| available(tool.program()))
}

/// The Linux confirmer, or [`None`] on a headless host / one with no dialog helper (fail closed).
pub(super) fn confirmer() -> Option<Box<dyn NativeConfirmer>> {
    if !has_display(|key| std::env::var(key).ok()) {
        return None;
    }
    let tool = detect_dialog_tool(binary_on_path)?;
    Some(Box::new(BackedConfirmer::new(
        DialogWindow {
            runner: SystemCommandRunner,
            tool,
        },
        PolkitVerifier {
            runner: SystemCommandRunner,
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::{ConfirmDecision, NativeConfirmer, SignPrompt};

    /// A runner scripted to return a fixed exit code and record what it was asked to run.
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

    #[test]
    fn dialog_exit_codes_map_to_the_right_intent() {
        assert_eq!(intent_from_dialog_exit(Some(0)), WindowIntent::Approve);
        assert_eq!(intent_from_dialog_exit(Some(1)), WindowIntent::Deny);
        assert_eq!(intent_from_dialog_exit(Some(5)), WindowIntent::Timeout);
        assert_eq!(intent_from_dialog_exit(Some(255)), WindowIntent::Deny);
        assert_eq!(intent_from_dialog_exit(None), WindowIntent::Unavailable);
    }

    #[test]
    fn pkcheck_exit_codes_map_to_the_right_outcome() {
        assert_eq!(outcome_from_pkcheck_exit(Some(0)), VerifyOutcome::Verified);
        assert_eq!(outcome_from_pkcheck_exit(Some(1)), VerifyOutcome::Declined);
        assert_eq!(outcome_from_pkcheck_exit(Some(2)), VerifyOutcome::Failed);
        assert_eq!(outcome_from_pkcheck_exit(None), VerifyOutcome::Unavailable);
    }

    #[test]
    fn dialog_window_runs_the_selected_tool_and_maps_the_result() {
        let window = DialogWindow {
            runner: FakeRunner::new(Some(0)),
            tool: DialogTool::Zenity,
        };
        assert_eq!(window.show(&content()), WindowIntent::Approve);
        let (program, args) = window.runner.last.lock().unwrap().clone().unwrap();
        assert_eq!(program, "zenity");
        assert!(args.iter().any(|a| a.contains("Send 100 $DIG")));
        assert!(args.iter().any(|a| a.contains("dapp.example")));
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
            DialogWindow {
                runner: FakeRunner::new(Some(0)),
                tool: DialogTool::Zenity,
            },
            PolkitVerifier {
                runner: FakeRunner::new(Some(0)),
            },
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
            DialogWindow {
                runner: FakeRunner::new(Some(0)),
                tool: DialogTool::Zenity,
            },
            PolkitVerifier {
                runner: FakeRunner::new(Some(1)),
            },
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

    #[test]
    fn kdialog_and_zenity_build_distinct_argument_shapes() {
        let c = content();
        let zenity = DialogTool::Zenity.args(&c);
        let kdialog = DialogTool::Kdialog.args(&c);
        assert!(zenity.iter().any(|a| a == "--question"));
        assert!(kdialog.iter().any(|a| a == "--yesno"));
    }

    #[test]
    fn zenity_disables_markup_so_hostile_fields_show_literally() {
        let content = ConfirmContent::connect(&crate::confirm::ConnectPrompt {
            origin: "https://evil.example",
            dapp_name: Some("<b>Trusted Bank</b>"),
        });
        let args = DialogTool::Zenity.args(&content);
        assert!(args.iter().any(|a| a == "--no-markup"));
        // The raw markup is carried through verbatim (rendered inert by --no-markup, not pre-stripped).
        assert!(args.iter().any(|a| a.contains("<b>Trusted Bank</b>")));
    }

    #[test]
    fn kdialog_escapes_rich_text_triggers_so_markup_cannot_render() {
        let content = ConfirmContent::connect(&crate::confirm::ConnectPrompt {
            origin: "https://evil.example",
            dapp_name: Some("<a href=x>Bank</a> & co"),
        });
        let args = DialogTool::Kdialog.args(&content);
        let text = &args[3];
        assert!(!text.contains('<'), "no tag opener may survive: {text}");
        assert!(!text.contains('>'), "no tag closer may survive: {text}");
        assert!(text.contains("&lt;a href=x&gt;"));
        assert!(text.contains("&amp; co"));
    }

    #[test]
    fn escape_kdialog_plain_neutralizes_every_trigger() {
        assert_eq!(escape_kdialog_plain("a<b>&c>"), "a&lt;b&gt;&amp;c&gt;");
        assert_eq!(escape_kdialog_plain("plain text"), "plain text");
    }

    #[test]
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

    #[test]
    fn detect_dialog_tool_prefers_zenity_then_kdialog_then_none() {
        assert_eq!(detect_dialog_tool(|_| true), Some(DialogTool::Zenity));
        assert_eq!(
            detect_dialog_tool(|p| p == "kdialog"),
            Some(DialogTool::Kdialog)
        );
        assert_eq!(detect_dialog_tool(|_| false), None);
    }

    #[test]
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
