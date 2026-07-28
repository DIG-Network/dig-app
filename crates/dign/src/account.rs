//! `dign account` — the command-line half of the DIG Account (dig_ecosystem#1752).
//!
//! # Why these verbs are LOCAL, not gateway commands
//!
//! Every other `dign` verb is a message to the running dig-app. These two cannot be:
//!
//! - **`restore`** exists precisely when there is no account for the app to serve. It has to reach the
//!   custody store on this machine directly.
//! - **`status`** must answer "is there an account here?" even when dig-app is not running, which is
//!   exactly when a person asks the question.
//!
//! Both address the account through [`AppEnvironment::from_host`], the same resolution the tray shell
//! uses, so the CLI and the app are provably talking about the same directory.
//!
//! # Why restore lives in the CLI at all
//!
//! A recovery phrase is 24 words of typed input, and a system-tray menu has no text field — the OS gives
//! a tray only menu items and message boxes. So the tray *points* at this command (see the shell's
//! `explain_restore`) instead of pretending it can take the words itself. The phrase is read with echo
//! suppressed so it never lands in terminal scrollback.

use std::io::IsTerminal;

use dig_app_core::account::boot::{
    account_exists, boot_existing_account, open_account, BootedAccount,
};
use dig_app_core::account::lifecycle::Seeding;
use dig_app_core::account::recovery::{RecoveryPhrase, PHRASE_WORDS};
use dig_app_core::environment::AppEnvironment;

/// What an account verb produced — rendered by the caller as prose or JSON.
#[derive(Debug, PartialEq, Eq)]
pub enum AccountReport {
    /// No account is enrolled on this host.
    NotSetUp,
    /// An account exists. `dig_id` is present only when it could be unlocked to read it.
    Present {
        /// The root profile's DIG ID, if the account unlocked.
        dig_id: Option<String>,
        /// Whether a recovery phrase is stored for it.
        recoverable: bool,
    },
    /// A restore completed and the account is now on this host.
    Restored {
        /// The restored account's DIG ID.
        dig_id: String,
    },
}

/// Why an account verb could not complete. Each is a situation the user can act on, so each says what
/// to do rather than only what failed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AccountCliError {
    /// The per-user data directory could not be resolved.
    #[error("could not work out where DIG keeps your data on this system: {0}")]
    NoDataDir(String),

    /// A restore was attempted on a host that already has an account.
    #[error(
        "this computer already has a DIG Account, and restoring would replace it. \
         Nothing was changed. If you mean to replace it, remove the existing account first."
    )]
    AlreadyHasAccount,

    /// The phrase could not be read from the terminal.
    #[error("could not read your recovery phrase: {0}")]
    NoInput(String),

    /// The words were not a valid recovery phrase.
    #[error("{0}")]
    BadPhrase(String),

    /// The restore itself failed — a keystore or credential-store problem.
    #[error(
        "the account could not be created from that phrase. Nothing was changed on this computer; \
         the log folder has the details."
    )]
    RestoreFailed,
}

/// Report what account, if any, this host has.
///
/// Deliberately does not force an unlock: on a host where the account cannot be unlocked (no credential
/// store, a locked keychain) the honest answer is still "there IS an account here", which is the fact the
/// user asked for.
pub fn status() -> Result<AccountReport, AccountCliError> {
    let dir = brand_dir()?;
    if !account_exists(&dir) {
        return Ok(AccountReport::NotSetUp);
    }
    // An unlock may legitimately fail (no credential store on this OS); that costs us the DIG ID and the
    // recoverable flag, not the answer. `boot_existing_account` can only unlock, never enrol, so asking
    // for status can never create an account as a side effect.
    match boot_existing_account(&dir) {
        Some(BootedAccount {
            profile_id,
            recoverable,
            ..
        }) => Ok(AccountReport::Present {
            dig_id: Some(profile_id),
            recoverable,
        }),
        None => Ok(AccountReport::Present {
            dig_id: None,
            recoverable: false,
        }),
    }
}

/// Restore an account from a recovery phrase read from `input`.
///
/// Split from the terminal read so the whole decision path — refuse when an account exists, reject a bad
/// phrase, enrol from a good one — is testable without a TTY.
pub fn restore_from(input: &str) -> Result<AccountReport, AccountCliError> {
    let dir = brand_dir()?;
    if account_exists(&dir) {
        return Err(AccountCliError::AlreadyHasAccount);
    }
    let phrase =
        RecoveryPhrase::parse(input).map_err(|why| AccountCliError::BadPhrase(why.to_string()))?;

    match open_account(&dir, Seeding::Restore(&phrase)) {
        Some(booted) => Ok(AccountReport::Restored {
            dig_id: booted.profile_id,
        }),
        None => Err(AccountCliError::RestoreFailed),
    }
}

/// Prompt for the recovery phrase on the terminal (echo suppressed) and restore from it.
pub fn restore_interactive() -> Result<AccountReport, AccountCliError> {
    // Refuse a piped stdin for the PROMPT path: a phrase arriving through a pipe usually means it is
    // sitting in a shell history or a file, so the user is told to type it instead.
    if !std::io::stdin().is_terminal() {
        return Err(AccountCliError::NoInput(
            "run this in a terminal and type your words — reading a recovery phrase from a pipe \
             would leave it in your shell history"
                .to_string(),
        ));
    }
    eprintln!(
        "Type your {PHRASE_WORDS} recovery words, separated by spaces, then press Enter.\n\
         They will not be shown as you type."
    );
    let typed = rpassword::prompt_password("Recovery phrase: ")
        .map_err(|e| AccountCliError::NoInput(e.to_string()))?;
    restore_from(&typed)
}

/// The per-user DIG data directory, resolved the same way the tray shell resolves it.
fn brand_dir() -> Result<std::path::PathBuf, AccountCliError> {
    AppEnvironment::from_host()
        .brand_dir()
        .map_err(|e| AccountCliError::NoDataDir(e.to_string()))
}

/// Render `report` as the human line the CLI prints.
pub fn describe(report: &AccountReport) -> String {
    match report {
        AccountReport::NotSetUp => "No DIG Account on this computer yet. Open the DIG menu from your \
             system tray and choose \"Set up my DIG Account\", or run `dign account restore` if you \
             already have a recovery phrase."
            .to_string(),
        AccountReport::Present {
            dig_id,
            recoverable,
        } => {
            let id = dig_id.as_deref().unwrap_or("(locked — could not be read)");
            let recovery = if *recoverable {
                "It has a recovery phrase; you can view it from the DIG tray menu."
            } else {
                "WARNING: it has NO recovery phrase, so it exists only on this computer and cannot \
                 be recovered if you lose it."
            };
            format!("You have a DIG Account.\n  DIG ID: {id}\n  {recovery}")
        }
        AccountReport::Restored { dig_id } => format!(
            "Your DIG Account has been restored on this computer.\n  DIG ID: {dig_id}\n  \
             Restart DIG so the tray picks it up."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A phrase-less account must read as a WARNING, not as a neutral fact — the copy is the only place
    /// a CLI user learns their account is unrecoverable.
    #[test]
    fn a_phrase_less_account_is_described_as_a_warning() {
        let text = describe(&AccountReport::Present {
            dig_id: Some("abc".to_string()),
            recoverable: false,
        });
        assert!(text.contains("NO recovery phrase"), "{text}");
        assert!(text.contains("cannot \n                 be recovered") || text.contains("cannot"));
    }

    /// A recoverable account must NOT carry the warning — the control proving the description reads the
    /// flag rather than always warning.
    #[test]
    fn a_recoverable_account_is_described_without_the_warning() {
        let text = describe(&AccountReport::Present {
            dig_id: Some("abc".to_string()),
            recoverable: true,
        });
        assert!(!text.contains("WARNING"), "{text}");
        assert!(text.contains("has a recovery phrase"), "{text}");
    }

    /// A locked account still reports itself as PRESENT — the answer the user asked for — and says why
    /// the id is missing instead of printing an empty field.
    #[test]
    fn a_locked_account_still_reports_itself_present() {
        let text = describe(&AccountReport::Present {
            dig_id: None,
            recoverable: false,
        });
        assert!(text.contains("You have a DIG Account"), "{text}");
        assert!(text.contains("locked"), "{text}");
    }

    #[test]
    fn a_host_with_no_account_is_pointed_at_both_ways_in() {
        let text = describe(&AccountReport::NotSetUp);
        assert!(text.contains("Set up my DIG Account"), "{text}");
        assert!(text.contains("dign account restore"), "{text}");
    }

    /// A restore tells the user the one thing they must do next. Without it they would sit in front of a
    /// tray still showing "not set up" and conclude the restore failed.
    #[test]
    fn a_restore_tells_the_user_to_restart_dig() {
        let text = describe(&AccountReport::Restored {
            dig_id: "deadbeef".to_string(),
        });
        assert!(text.contains("Restart DIG"), "{text}");
        assert!(text.contains("deadbeef"), "{text}");
    }

    /// Every error must state that nothing was changed, or say what to do — a CLI that reports a custody
    /// failure without saying whether it half-completed leaves the user unable to act.
    #[test]
    fn the_already_has_account_error_promises_nothing_changed() {
        let text = AccountCliError::AlreadyHasAccount.to_string();
        assert!(text.contains("Nothing was changed"), "{text}");
    }

    #[test]
    fn the_restore_failed_error_promises_nothing_changed_and_points_at_the_logs() {
        let text = AccountCliError::RestoreFailed.to_string();
        assert!(text.contains("Nothing was changed"), "{text}");
        assert!(text.contains("log folder"), "{text}");
    }

    /// A bad phrase surfaces the parser's own reason (wrong length vs invalid), because "check for a
    /// mistyped word" and "you typed 12 words" need different actions from the user.
    #[test]
    fn a_bad_phrase_error_carries_the_parsers_reason() {
        let short = RecoveryPhrase::parse("abandon abandon").unwrap_err();
        let text = AccountCliError::BadPhrase(short.to_string()).to_string();
        assert!(text.contains("24 words"), "{text}");
        assert!(text.contains("has 2"), "{text}");
    }
}
