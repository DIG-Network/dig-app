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

use zeroize::{Zeroize, Zeroizing};

use super::{
    BackedConfirmer, BiometricVerifier, ConfirmContent, ForegroundInput, ForegroundWindow,
    InputContent, InputOutcome, NativeConfirmer, Presentation, VerifyOutcome, WindowIntent,
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

    /// Run `program args…` and return its exit code **plus its standard output**.
    ///
    /// Needed only by the input helpers (dig_ecosystem#1798), whose ANSWER is the text on stdout rather
    /// than a code: `zenity --entry` and `kdialog --password` print what the user typed. The output is
    /// [`Zeroizing`] because for DIG that text is a recovery phrase.
    fn run_capturing(&self, program: &str, args: &[String]) -> Option<(i32, Zeroizing<String>)>;
}

/// The production runner: actually spawns the helper process.
struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[String]) -> Option<i32> {
        Command::new(program).args(args).status().ok()?.code()
    }

    fn run_capturing(&self, program: &str, args: &[String]) -> Option<(i32, Zeroizing<String>)> {
        // `output()` inherits stderr, so a helper's own diagnostics still reach the log, while only the
        // typed answer is captured.
        let mut output = Command::new(program).args(args).output().ok()?;
        // The RAW bytes are the recovery phrase, so the `Vec` `Command` allocated is wiped too — not just
        // the `String` copied out of it (dig_ecosystem#1799 review). `from_utf8_lossy` borrows, so without
        // this the phrase would sit in that buffer until the allocator happened to reuse it.
        let text = Zeroizing::new(String::from_utf8_lossy(&output.stdout).to_string());
        output.stdout.zeroize();
        Some((output.status.code()?, text))
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

    /// The argument vector that shows `content`: a modal **question** dialog with an approve/cancel choice
    /// for a real either/or, or a one-button **information** dialog for a notice (dig_ecosystem#1773). Both
    /// self-dismiss after [`DIALOG_TIMEOUT_SECS`] where the helper supports it.
    ///
    /// **Markup safety (security-critical).** The displayed text carries attacker-influenced fields
    /// (the dapp name / extension label, and — once the loopback wires them — the decoded transaction
    /// and its `payload_type`). Both helpers can INTERPRET markup in their text (`zenity --text` reads
    /// Pango markup; `kdialog` renders the string as Qt rich text when it looks HTML-ish), so a hostile
    /// field could cosmetically distort what the user believes they are approving. Each helper is
    /// therefore forced to treat the text as PLAIN: `zenity` via `--no-markup`, `kdialog` by escaping
    /// the rich-text trigger characters so `mightBeRichText` can never fire. This holds for BOTH dialog
    /// kinds — a notice also carries caller-composed text, and losing the neutralization on one branch
    /// would reintroduce the whole class.
    /// **`refusal_is_default` is deliberately not honoured here, and that is currently unreachable rather
    /// than a gap.** Neither helper has a "make Cancel the default" flag, and the only window that asks for
    /// one is the destroy authorization — which cannot be drawn on Linux at all: with no per-application
    /// credential store the account state is always `Unsupported`, and the management submenu offers only the
    /// DID explainer there. A Linux credential store MUST NOT land without revisiting this (`SPEC.md` §3.1d).
    fn args(self, content: &ConfirmContent) -> Vec<String> {
        let text = format!("{}\n\n{}", content.heading, content.body);
        let decides = matches!(content.presentation, Presentation::Decide { .. });
        match self {
            Self::Zenity if decides => vec![
                "--question".into(),
                "--no-markup".into(),
                format!("--title={}", content.title),
                format!("--text={text}"),
                format!("--ok-label={}", content.action),
                "--cancel-label=Cancel".into(),
                format!("--timeout={DIALOG_TIMEOUT_SECS}"),
            ],
            Self::Zenity => vec![
                "--info".into(),
                "--no-markup".into(),
                format!("--title={}", content.title),
                format!("--text={text}"),
                format!("--ok-label={}", content.action),
                format!("--timeout={DIALOG_TIMEOUT_SECS}"),
            ],
            Self::Kdialog if decides => vec![
                "--title".into(),
                content.title.clone(),
                "--yesno".into(),
                escape_kdialog_plain(&text),
                "--yes-label".into(),
                content.action.into(),
                "--no-label".into(),
                "Cancel".into(),
            ],
            // `--msgbox` is kdialog's one-button information dialog. It has no `--ok-label`, so the
            // affirmative label is not carried through here; a notice's label is always a plain dismissal
            // ("OK", "Done"), so nothing a user needs is lost.
            Self::Kdialog => vec![
                "--title".into(),
                content.title.clone(),
                "--msgbox".into(),
                escape_kdialog_plain(&text),
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

impl DialogTool {
    /// The argument vector that asks the user to TYPE something (dig_ecosystem#1798).
    ///
    /// Both helpers print the typed text on stdout and exit `0`; cancelling exits non-zero with no output.
    /// **Markup safety** is handled the same way as [`args`](Self::args) — `zenity` is forced to
    /// `--no-markup` and `kdialog`'s rich-text triggers are escaped — because this text is also
    /// caller-composed and the class of defect does not care which dialog kind it lands in.
    ///
    /// Neither helper offers a MULTI-LINE entry, so a 24-word phrase is typed on one line. That is what the
    /// `dign` prompt did too, and it is the one place the Linux window is poorer than the Win32 one; it is
    /// still a native GUI field, which is the property that matters.
    fn input_args(self, content: &InputContent) -> Vec<String> {
        let text = format!(
            "{}\n\n{}\n\n{}",
            content.heading, content.body, content.field_label
        );
        match self {
            Self::Zenity => {
                let mut args = vec![
                    "--entry".into(),
                    "--no-markup".into(),
                    format!("--title={}", content.title),
                    format!("--text={text}"),
                    format!("--ok-label={}", content.submit),
                    "--cancel-label=Cancel".into(),
                ];
                if content.masked {
                    args.push("--hide-text".into());
                }
                args
            }
            Self::Kdialog => vec![
                "--title".into(),
                content.title.clone(),
                match content.masked {
                    true => "--password".into(),
                    false => "--inputbox".into(),
                },
                escape_kdialog_plain(&text),
            ],
        }
    }
}

/// A [`ForegroundInput`] backed by a desktop dialog helper's entry dialog.
struct EntryWindow<R: CommandRunner> {
    runner: R,
    tool: DialogTool,
}

impl<R: CommandRunner> ForegroundInput for EntryWindow<R> {
    fn ask(&self, content: &InputContent) -> InputOutcome {
        let captured = self
            .runner
            .run_capturing(self.tool.program(), &self.tool.input_args(content));
        outcome_from_entry(captured)
    }
}

/// Map an entry helper's (exit code, stdout) to an outcome.
///
/// Only exit `0` means the user submitted. A non-zero code is a cancel — and any text captured alongside it
/// is DISCARDED rather than returned, because a helper that failed may have printed a usage message that
/// must never be mistaken for a recovery phrase. A helper that could not be spawned is
/// [`InputOutcome::Unavailable`], so the caller fails closed.
///
/// The trailing newline the helpers add is stripped here, at the boundary, so no caller has to know that
/// these particular helpers append one.
fn outcome_from_entry(captured: Option<(i32, Zeroizing<String>)>) -> InputOutcome {
    match captured {
        Some((0, text)) => InputOutcome::Provided(Zeroizing::new(
            text.trim_end_matches(['\n', '\r']).to_string(),
        )),
        Some(_) => InputOutcome::Cancelled,
        None => InputOutcome::Unavailable,
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
    use crate::confirm::{ConfirmDecision, NativeConfirmer, NoInputWindow, SignPrompt};

    /// A runner scripted to return a fixed exit code — and, for the input helpers, a fixed stdout — while
    /// recording what it was asked to run.
    ///
    /// `stdout` is a SEPARATE field from `code` on purpose: the entry helpers can exit non-zero while still
    /// having printed something, and a double that could only vary one of the two could not express that
    /// case — which is the one where a usage message must NOT be mistaken for a recovery phrase.
    struct FakeRunner {
        code: Option<i32>,
        stdout: String,
        last: std::sync::Mutex<Option<(String, Vec<String>)>>,
    }
    impl FakeRunner {
        fn new(code: Option<i32>) -> Self {
            Self {
                code,
                stdout: String::new(),
                last: std::sync::Mutex::new(None),
            }
        }

        /// The same runner, but printing `stdout` — for the entry helpers, whose answer is their output.
        fn printing(code: Option<i32>, stdout: &str) -> Self {
            Self {
                stdout: stdout.to_string(),
                ..Self::new(code)
            }
        }
    }
    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[String]) -> Option<i32> {
            *self.last.lock().unwrap() = Some((program.to_string(), args.to_vec()));
            self.code
        }

        fn run_capturing(
            &self,
            program: &str,
            args: &[String],
        ) -> Option<(i32, Zeroizing<String>)> {
            *self.last.lock().unwrap() = Some((program.to_string(), args.to_vec()));
            Some((self.code?, Zeroizing::new(self.stdout.clone())))
        }
    }

    fn input_content(masked: bool) -> InputContent {
        InputContent {
            title: "DIG - Restore".to_string(),
            heading: "Type your 24-word recovery phrase.".to_string(),
            body: "Words in order, separated by spaces.".to_string(),
            field_label: "Your 24 words:".to_string(),
            submit: "Restore",
            masked,
            revealable: true,
            // Linux draws every input on its dialog helper, which has no frameless mode — the launcher
            // bar falls back to the ordinary dialog here (see `InputStyle`).
            style: crate::confirm::InputStyle::Dialog,
        }
    }

    /// The entry helper's typed answer must come back, with the trailing newline both helpers append
    /// stripped at this boundary — a phrase carrying a stray newline would fail BIP-39 parsing for a
    /// reason the user could never see.
    #[test]
    fn a_submitted_entry_returns_the_typed_text_without_its_trailing_newline() {
        let window = EntryWindow {
            // A CRLF, not just a newline: `kdialog` on some desktops appends one, and a fixture using only
            // "\n" would pass for a trim that removed a single character.
            runner: FakeRunner::printing(Some(0), "abandon abandon ability\r\n"),
            tool: DialogTool::Zenity,
        };
        match window.ask(&input_content(false)) {
            InputOutcome::Provided(text) => {
                assert_eq!(&*text, "abandon abandon ability")
            }
            other => panic!("expected the typed text, got {other:?}"),
        }
    }

    /// **The control that makes the test above load-bearing.** A helper that exits non-zero has CANCELLED,
    /// and anything it printed (a usage message, a warning) must be discarded rather than returned — an
    /// implementation that read stdout regardless of the code would pass the test above and fail here.
    #[test]
    fn a_cancelled_entry_discards_anything_the_helper_printed() {
        let window = EntryWindow {
            runner: FakeRunner::printing(Some(1), "Usage: zenity [OPTION...]\n"),
            tool: DialogTool::Zenity,
        };
        assert!(matches!(
            window.ask(&input_content(false)),
            InputOutcome::Cancelled
        ));
    }

    /// A helper that could not be spawned must report UNAVAILABLE, never an empty answer — the caller has
    /// to be able to tell "the user typed nothing" from "the user was never asked".
    #[test]
    fn an_unspawnable_entry_helper_is_unavailable_not_an_empty_answer() {
        let window = EntryWindow {
            runner: FakeRunner::printing(None, ""),
            tool: DialogTool::Kdialog,
        };
        assert!(matches!(
            window.ask(&input_content(false)),
            InputOutcome::Unavailable
        ));
    }

    /// Masking must be requested only when asked for, on BOTH helpers — a phrase field forced to
    /// `--hide-text` makes 24 words untypeable, and a passphrase field that echoes leaks it to the room.
    #[test]
    fn the_entry_helpers_mask_only_when_the_prompt_asks() {
        for (tool, masked_marker) in [
            (DialogTool::Zenity, "--hide-text"),
            (DialogTool::Kdialog, "--password"),
        ] {
            let masked = tool.input_args(&input_content(true));
            let plain = tool.input_args(&input_content(false));
            assert!(
                masked.iter().any(|a| a == masked_marker),
                "{tool:?} must mask when asked: {masked:?}"
            );
            assert!(
                !plain.iter().any(|a| a == masked_marker),
                "{tool:?} must NOT mask a 24-word phrase: {plain:?}"
            );
        }
    }

    /// **Markup safety.** The entry dialog carries caller-composed text too, so it must be forced to plain
    /// text exactly like the confirm dialog is — losing the neutralization on this branch would reintroduce
    /// the whole class on a new surface.
    #[test]
    fn the_entry_dialog_is_forced_to_plain_text() {
        let zenity = DialogTool::Zenity.input_args(&input_content(false));
        assert!(zenity.iter().any(|a| a == "--no-markup"), "{zenity:?}");

        let hostile = InputContent {
            heading: "<b>Type</b> your phrase".to_string(),
            ..input_content(false)
        };
        let kdialog = DialogTool::Kdialog.input_args(&hostile);
        assert!(
            kdialog.iter().any(|a| a.contains("&lt;b&gt;")),
            "kdialog's rich-text triggers must be escaped: {kdialog:?}"
        );
        assert!(!kdialog.iter().any(|a| a.contains("<b>")), "{kdialog:?}");
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
            DialogWindow {
                runner: FakeRunner::new(Some(0)),
                tool: DialogTool::Zenity,
            },
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

    /// The notice content the tray draws eleven of — informational, nothing to decline.
    fn notice_content() -> ConfirmContent {
        ConfirmContent::notice(&crate::confirm::NoticePrompt {
            title: "DIG — DIG ID copied",
            heading: "Your DIG ID is on the clipboard.",
            body: "abc123",
            acknowledge: "OK",
        })
    }

    /// **Regression (#1773).** A notice is an INFORMATION dialog with one button on both helpers; a real
    /// either/or keeps its question framing and its Cancel.
    ///
    /// Both directions are asserted together deliberately: a test that only checked "the notice has no
    /// Cancel" would pass just as well on an implementation that stripped Cancel from EVERY dialog,
    /// silently destroying the way out of the reveal gate and the retention claim.
    #[test]
    fn a_notice_is_an_information_dialog_and_a_decision_keeps_its_cancel() {
        let notice = notice_content();
        let decision = content(); // a sign authorization

        let zenity_notice = DialogTool::Zenity.args(&notice);
        assert!(zenity_notice.iter().any(|a| a == "--info"));
        assert!(
            !zenity_notice.iter().any(|a| a.contains("cancel-label")),
            "a notice offers nothing to cancel: {zenity_notice:?}"
        );

        let zenity_decision = DialogTool::Zenity.args(&decision);
        assert!(zenity_decision.iter().any(|a| a == "--question"));
        assert!(zenity_decision.iter().any(|a| a == "--cancel-label=Cancel"));

        let kdialog_notice = DialogTool::Kdialog.args(&notice);
        assert!(kdialog_notice.iter().any(|a| a == "--msgbox"));
        assert!(!kdialog_notice.iter().any(|a| a == "--no-label"));

        assert!(DialogTool::Kdialog
            .args(&decision)
            .iter()
            .any(|a| a == "--yesno"));
    }

    /// The markup neutralization must survive on the notice branch too. The fixture puts hostile markup in
    /// a NOTICE's body — the branch that did not exist before this change — because the pre-existing tests
    /// only ever exercised the question branch and would score a notice that renders raw HTML as fine.
    #[test]
    fn the_notice_branch_neutralizes_markup_on_both_helpers() {
        let hostile = ConfirmContent::notice(&crate::confirm::NoticePrompt {
            title: "DIG — Logs",
            heading: "DIG could not open the folder for you.",
            body: "<b>C:\\evil</b> & co",
            acknowledge: "OK",
        });

        assert!(DialogTool::Zenity
            .args(&hostile)
            .iter()
            .any(|a| a == "--no-markup"));

        let kdialog = DialogTool::Kdialog.args(&hostile);
        let text = &kdialog[3];
        assert!(!text.contains('<'), "no tag opener may survive: {text}");
        assert!(text.contains("&lt;b&gt;"));
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
