//! The TERMINAL half of the account password prompt (dig_ecosystem#1817).
//!
//! # Why this exists
//!
//! [`PasswordCeremony`](dig_app_core::account::passphrase::PasswordCeremony) asks its questions through
//! [`NativeConfirmer::request_input`] — a desktop window. `dign` has no window and does not want one: a
//! person running a CLI expects the CLI to ask. So this is a [`NativeConfirmer`] whose ONLY implemented
//! method is `request_input`, answered on the terminal with echo suppressed.
//!
//! Reusing the ceremony rather than writing a second password flow here is the point. The length bar, the
//! type-it-twice rule, the bounded re-ask and the copy that explains what a forgotten password costs are
//! all custody policy, and a CLI with its own copy of that policy is a CLI that drifts from it.
//!
//! # Why every other method refuses
//!
//! `dign` cannot raise a biometric prompt, so it cannot authorize a signature, a pairing or a
//! destruction. Every one of those returns [`ConfirmDecision::Unavailable`] — fail closed — rather than
//! approving something no human was asked about. The one exception is [`show_notice`], which prints:
//! telling the user something is always safe.

use dig_app_core::confirm::{
    ConfirmDecision, ConnectPrompt, InputOutcome, InputPrompt, NativeConfirmer, NoticePrompt,
    PairPrompt, SignPrompt,
};

/// Asks for a password on the terminal, with echo suppressed.
pub struct TerminalPassword;

impl NativeConfirmer for TerminalPassword {
    fn confirm_pair(&self, _prompt: &PairPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }

    fn confirm_connect(&self, _prompt: &ConnectPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }

    fn confirm_sign(&self, _prompt: &SignPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }

    /// Print a notice on stderr, so the ceremony's explanations reach a CLI user too.
    ///
    /// stderr rather than stdout: `dign` reserves stdout for the machine-readable answer (§6.2), and a
    /// paragraph about recovery phrases in the middle of `--json` output would break every script.
    fn show_notice(&self, prompt: &NoticePrompt<'_>) -> ConfirmDecision {
        eprintln!("\n{}\n{}\n", prompt.heading, prompt.body);
        ConfirmDecision::Approve
    }

    /// Read the password from the terminal.
    ///
    /// Refuses a non-terminal stdin: a password arriving through a pipe is usually sitting in a shell
    /// history or a file, and [`InputOutcome::Unavailable`] makes the caller fail closed rather than treat
    /// the empty read as a submitted password.
    fn request_input(&self, prompt: &InputPrompt<'_>) -> InputOutcome {
        use std::io::IsTerminal;

        if !std::io::stdin().is_terminal() {
            eprintln!(
                "dign needs a terminal to ask for your DIG Account password — reading it from a pipe \
                 would leave it in your shell history."
            );
            return InputOutcome::Unavailable;
        }
        eprintln!("\n{}\n{}\n", prompt.heading, prompt.body);
        match rpassword::prompt_password(format!("{} ", prompt.field_label)) {
            // `rpassword` hands back a plain `String`; wrapping it immediately is what gets it scrubbed
            // on drop, matching the desktop window's `Zeroizing` buffer.
            Ok(typed) => InputOutcome::Provided(zeroize::Zeroizing::new(typed)),
            Err(e) => {
                eprintln!("could not read your password: {e}");
                InputOutcome::Cancelled
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every gate `dign` cannot honestly run must REFUSE. A CLI that approved a signature nobody was
    /// asked about would be a hole in the confirm gate, reachable by anything that can run `dign`.
    #[test]
    fn every_authorization_dign_cannot_ask_for_is_refused() {
        let cli = TerminalPassword;
        assert_eq!(
            cli.confirm_pair(&PairPrompt {
                ext_id: "id",
                ext_label: None
            }),
            ConfirmDecision::Unavailable
        );
        assert_eq!(
            cli.confirm_connect(&ConnectPrompt {
                origin: "https://dapp.example",
                dapp_name: None
            }),
            ConfirmDecision::Unavailable
        );
        assert_eq!(
            cli.confirm_sign(&SignPrompt {
                origin: "https://dapp.example",
                payload_type: "wallet.spend",
                decoded_tx: Some("anything at all")
            }),
            ConfirmDecision::Unavailable
        );
        // The two defaults the trait supplies are refusals too, and they matter most: a reveal and a
        // destroy are the gates a CLI must never be able to pass.
        assert_eq!(
            cli.confirm_reveal(&dig_app_core::confirm::RevealPrompt { secret: "words" }),
            ConfirmDecision::Unavailable
        );
        assert_eq!(
            cli.confirm_destroy(&dig_app_core::confirm::DestroyPrompt {
                subject: "the account",
                replacement: "nothing",
                recoverable: true
            }),
            ConfirmDecision::Unavailable
        );
    }

    /// A piped stdin must report that the password could not be ASKED for — never an empty answer, which
    /// is a real string a seal could be built on.
    ///
    /// `cargo test` runs with stdin redirected, so this exercises the real branch rather than a simulated
    /// one.
    #[test]
    fn a_piped_stdin_reports_that_it_could_not_ask() {
        let outcome = TerminalPassword.request_input(&InputPrompt {
            title: "t",
            heading: "h",
            body: "b",
            field_label: "Password:",
            submit: "Unlock",
            masked: true,
            reveal_label: Some("Show my password while I type"),
        });
        assert!(matches!(outcome, InputOutcome::Unavailable));
    }
}
