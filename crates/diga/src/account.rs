//! `diga account` — the command-line half of the DIG Account (dig_ecosystem#1752).
//!
//! # Why these verbs are LOCAL, not gateway commands
//!
//! Every other `diga` verb is a message to the running dig-app. These two cannot be:
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

use dig_app_core::account::boot::{open_account, seed_presence, SeedPresence};
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
        /// The root profile's DIG ID, if the account was open enough to read it.
        dig_id: Option<String>,
        /// Whether a recovery phrase is stored for it, or `None` when that is not KNOWN.
        ///
        /// Three-valued rather than a `bool` because reading the flag requires unlocking the account,
        /// and since dig_ecosystem#1817 an unlock needs the user's password — which `diga account
        /// status` has no business demanding just to answer "do I have an account?". A `bool` here
        /// would have to guess, and the only available guess (`false`) prints a WARNING telling the
        /// user their account has no recovery phrase, which for most accounts is simply untrue.
        recoverable: Option<bool>,
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

    /// Whether this host holds an account could not be determined at all.
    ///
    /// Distinct from [`NotSetUp`](AccountReport::NotSetUp) and from
    /// [`AlreadyHasAccount`](Self::AlreadyHasAccount) because it is neither: the custody root could not
    /// be read, so both of those sentences would be inventions. It refuses rather than guessing, and a
    /// restore refuses along with it — a guess of "no account here" would enrol a new seed over one that
    /// may still be sitting there.
    #[error(
        "could not tell whether this computer has a DIG Account: the folder DIG keeps it in could \
         not be read. Nothing was changed. Check that the folder exists, is a real folder rather \
         than a shortcut, and that you can read it."
    )]
    PresenceUnknown,

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
    match seed_presence(&dir) {
        SeedPresence::Absent => return Ok(AccountReport::NotSetUp),
        SeedPresence::Undeterminable => return Err(AccountCliError::PresenceUnknown),
        SeedPresence::Present => {}
    }
    // Status reports what is at rest and unlocks NOTHING. Since dig_ecosystem#1817 an unlock draws a
    // password window, and a status query that popped one would train people to type their account
    // password at any prompt — the habit every credential-phishing attack relies on. So the DIG ID and
    // the recovery-phrase flag are reported as UNKNOWN rather than bought with a prompt.
    Ok(AccountReport::Present {
        dig_id: None,
        recoverable: None,
    })
}

/// Restore an account from a recovery phrase read from `input`.
///
/// Split from the terminal read so the whole decision path — refuse when an account exists, reject a bad
/// phrase, enrol from a good one — is testable without a TTY.
pub fn restore_from(input: &str) -> Result<AccountReport, AccountCliError> {
    let dir = brand_dir()?;
    // Only a DEFINITE absence may proceed: enrolling is a WRITE at the custody root, so an
    // undeterminable probe must refuse rather than fall through to "there is nothing here".
    match seed_presence(&dir) {
        SeedPresence::Present => return Err(AccountCliError::AlreadyHasAccount),
        SeedPresence::Undeterminable => return Err(AccountCliError::PresenceUnknown),
        SeedPresence::Absent => {}
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
             system tray and choose \"Set up my DIG Account\", or run `diga account restore` if you \
             already have a recovery phrase."
            .to_string(),
        AccountReport::Present {
            dig_id,
            recoverable,
        } => {
            let id = dig_id.as_deref().unwrap_or("(locked — unlock it from the DIG tray menu)");
            let recovery = match recoverable {
                Some(true) => "It has a recovery phrase; you can view it from the DIG tray menu.",
                Some(false) => {
                    "WARNING: it has NO recovery phrase, so it exists only on this computer and cannot \
                     be recovered if you lose it."
                }
                // Unknown is stated as unknown. Printing the WARNING here would tell most users their
                // account is unrecoverable when it is not.
                None => {
                    "Unlock it from the DIG tray menu to see its DIG ID and whether it has a recovery \
                     phrase."
                }
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
            recoverable: Some(false),
        });
        assert!(text.contains("NO recovery phrase"), "{text}");
        // Asserted on the RENDERED sentence. The previous form expected a literal newline and indentation
        // that the line-continuation removes, so its first clause could never match — and its
        // `|| text.contains("cannot")` fallback made the whole assertion unfailable. A substring test that
        // cannot fail is not a test; review found the same class in the tray's own copy
        // (dig_ecosystem#1799).
        assert!(
            text.contains("cannot be recovered if you lose it"),
            "{text}"
        );
    }

    /// A recoverable account must NOT carry the warning — the control proving the description reads the
    /// flag rather than always warning.
    #[test]
    fn a_recoverable_account_is_described_without_the_warning() {
        let text = describe(&AccountReport::Present {
            dig_id: Some("abc".to_string()),
            recoverable: Some(true),
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
            recoverable: None,
        });
        assert!(text.contains("You have a DIG Account"), "{text}");
        assert!(text.contains("locked"), "{text}");
    }

    /// **The trap this three-valued flag exists to avoid.** An account whose recovery-phrase state is
    /// simply UNKNOWN — because status refuses to demand a password to find out — must NOT be described
    /// as having no recovery phrase.
    ///
    /// A `bool` field could only render this case as one of the two certainties, and the honest-looking
    /// default (`false`) prints a WARNING that is wrong for every account created since recovery phrases
    /// landed. That is a scarier lie than saying nothing.
    #[test]
    fn an_unknown_recovery_state_is_never_reported_as_having_no_phrase() {
        let text = describe(&AccountReport::Present {
            dig_id: None,
            recoverable: None,
        });
        assert!(!text.contains("WARNING"), "{text}");
        assert!(!text.contains("NO recovery phrase"), "{text}");
        assert!(text.contains("whether it has a recovery"), "{text}");
    }

    #[test]
    fn a_host_with_no_account_is_pointed_at_both_ways_in() {
        let text = describe(&AccountReport::NotSetUp);
        assert!(text.contains("Set up my DIG Account"), "{text}");
        assert!(text.contains("diga account restore"), "{text}");
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
