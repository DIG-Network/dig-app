//! The tray STARTS LOCKED, and nothing can open an account without a password (dig_ecosystem#1817).
//!
//! # Why this is a source-level test
//!
//! The property is a property of `main`: that the tray mounts with no account open and no signing channel
//! listening, so the user's first unlock is a deliberate act. `main` cannot be called from a test — it
//! resolves the real host environment, installs the process logging stack and enters a platform event loop
//! — so there is no runtime seam to assert on. The alternative to reading the source is no coverage at all
//! on the single most important property of this change, and this crate already establishes the technique:
//! `tests/gui_subsystem.rs` parses the built binary's PE header for the same reason.
//!
//! # What actually keeps the guarantee
//!
//! The TYPE SIGNATURES, not this test. `start_sign_service` takes a `BootedAccount` it cannot produce, and
//! the only two functions that produce one — `open_account` and `unlock_existing_account` — both require an
//! `AuthCeremony`. So "there is no path from process start to a live signing channel that does not pass
//! through a password prompt" is enforced by the compiler.
//!
//! This test guards the one thing the compiler cannot: that `main` does not CALL one of those functions at
//! startup. A future edit that helpfully unlocked the account at login would compile, pass every unit test,
//! and silently restore the defect — the tray would come up open again, differing only in that it had
//! prompted. It fails here instead.

/// The shell source, read from the crate directory at compile time so the test cannot drift onto a stale
/// copy or a path that does not exist.
const SHELL: &str = include_str!("../src/bin/dig-app.rs");

/// The body of `fn main`, from its signature to the closing brace of the following item.
///
/// Bounded at the next top-level `fn`/`mod` rather than by brace counting: the aim is only to isolate the
/// startup path from the menu handlers below it, and a cheap bound that errs on the side of INCLUDING too
/// much is safe here — a false positive would be a real call in a real startup-adjacent function.
fn startup_path() -> &'static str {
    let start = SHELL
        .find("\nfn main() {")
        .expect("the shell must have a `fn main`");
    let rest = &SHELL[start + 1..];
    let end = rest
        .find("\n/// Mount the tray shell")
        .expect("`main` must be followed by `run_tray_or_headless`'s doc comment");
    &rest[..end]
}

/// **The headline guarantee**: startup opens no account.
///
/// Named individually rather than as a loop over one list, so a failure says WHICH way in reappeared.
#[test]
fn startup_never_unlocks_the_account() {
    let main = startup_path();
    assert!(
        !main.contains("unlock_existing_account"),
        "`main` must not unlock the account at startup — the tray starts LOCKED and the user unlocks \
         from the menu (dig_ecosystem#1817). Found a call in:\n{main}"
    );
    assert!(
        !main.contains("open_account"),
        "`main` must not open or enrol an account at startup: enrolling means showing a recovery phrase \
         nobody asked for, and opening means either a login-time password prompt or reaching the seed \
         without one. Found a call in:\n{main}"
    );
}

/// And startup brings up no signing channel, which is the security half: while the account is locked the
/// APP-SIGN loopback port is not refusing, it is not LISTENING.
#[test]
fn startup_never_starts_the_signing_channel() {
    let main = startup_path();
    assert!(
        !main.contains("start_sign_service"),
        "`main` must not start the APP-SIGN loopback channel at startup — it exists only over an account \
         the user has unlocked. Found a call in:\n{main}"
    );
}

/// The control that stops the two tests above from passing vacuously.
///
/// If `startup_path` ever stopped isolating the right region — a renamed `main`, a moved doc comment, a
/// refactor that emptied it — the assertions would hold over an empty string and prove nothing. So this
/// pins that the region really is the startup path, by requiring the things `main` unambiguously does.
#[test]
fn the_startup_path_this_test_reads_is_really_the_startup_path() {
    let main = startup_path();
    assert!(
        main.contains("Agent::from_env"),
        "the isolated region must be the one that builds the agent"
    );
    assert!(
        main.contains("FormFactor::Tray"),
        "the isolated region must be the one that decides tray-vs-headless"
    );
    assert!(
        main.contains("run_tray_or_headless"),
        "the isolated region must be the one that mounts the shell"
    );
    assert!(
        main.len() > 500,
        "the isolated region is suspiciously short ({} bytes) — the bounds have drifted",
        main.len()
    );
}

/// Every account the shell opens is opened through a password ceremony.
///
/// A weaker but broader companion to the compiler's guarantee: it pins that no call site anywhere in the
/// shell passes something other than a `PasswordCeremony`, which is what a future "convenience" ceremony
/// would look like on its way in.
#[test]
fn every_account_the_shell_opens_is_opened_with_a_password_ceremony() {
    let opens = SHELL.matches("open_account(").count();
    let unlocks = SHELL.matches("unlock_existing_account(").count();
    let ceremonies = SHELL.matches("PasswordCeremony::").count();
    assert!(
        opens + unlocks > 0,
        "the shell must still open accounts somewhere, or this test is vacuous"
    );
    assert!(
        ceremonies >= opens + unlocks,
        "every account the shell opens must be opened through a PasswordCeremony: {opens} open_account \
         + {unlocks} unlock_existing_account call(s) against only {ceremonies} ceremon(ies)"
    );
    assert!(
        !SHELL.contains("CredentialCeremony"),
        "the zero-prompt credential-store ceremony is deleted and must not come back"
    );
}
