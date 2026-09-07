//! Regression test for dig-app#400: `diga` must parse argv BEFORE initializing logging, so
//! `--version`/`--help` never touch the log directory and never print anything but clap's own
//! output — and any command that DOES run must still keep its logging-setup warnings off stdout.
//!
//! The unwritable log dir is made portably (not with permission bits, which don't degrade the
//! same way on Windows): `DIG_LOG_DIR` points at `<tempdir>/<a regular file>/logs`, so
//! `create_dir_all` fails on every OS because a path component is a file, not a directory.

use std::io::Write;
use std::process::Command;

/// Build a `DIG_LOG_DIR` value whose parent path component is a plain file, guaranteeing
/// `std::fs::create_dir_all` fails identically on Windows, macOS and Linux.
fn unwritable_log_dir(tmp: &tempfile::TempDir) -> std::path::PathBuf {
    let blocker = tmp.path().join("blocker-file");
    let mut f = std::fs::File::create(&blocker).expect("create the blocking file");
    writeln!(f, "not a directory").expect("write the blocking file");
    blocker.join("logs")
}

#[test]
fn version_touches_no_log_dir_and_prints_only_claps_line() {
    let tmp = tempfile::tempdir().expect("make a temp dir");
    let log_dir = unwritable_log_dir(&tmp);

    let output = Command::new(env!("CARGO_BIN_EXE_diga"))
        .arg("--version")
        .env("DIG_LOG_DIR", &log_dir)
        .output()
        .expect("spawn diga --version");

    assert!(
        output.status.success(),
        "diga --version exited with {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "diga --version must be silent on stderr when logging cannot be set up (init must run \
         AFTER parse, so --version never reaches dig_logging::init); got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected_stdout = format!("diga {}\n", env!("CARGO_PKG_VERSION"));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        expected_stdout,
        "stdout must be EXACTLY clap's version line -- the update beacon (dig_ecosystem#1749) \
         parses the last token of the first line"
    );
}

#[test]
fn help_touches_no_log_dir_and_prints_only_claps_help() {
    let tmp = tempfile::tempdir().expect("make a temp dir");
    let log_dir = unwritable_log_dir(&tmp);

    let output = Command::new(env!("CARGO_BIN_EXE_diga"))
        .arg("--help")
        .env("DIG_LOG_DIR", &log_dir)
        .output()
        .expect("spawn diga --help");

    assert!(
        output.status.success(),
        "diga --help exited with {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "diga --help must be silent on stderr when logging cannot be set up; got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("The DIG user CLI"),
        "stdout must contain clap's `about` line; got: {stdout}"
    );
}

/// A command that DOES run (not --version/--help) must still keep any logging-setup warning off
/// stdout: `--json` output must be exactly one JSON object. This does not require the log dir to
/// succeed -- dig-logging degrades to console-only logging and diga's own gateway call fails fast
/// with no app running -- it only requires that whichever warnings happen land on stderr.
#[test]
fn json_output_stays_one_json_object_even_when_the_log_dir_is_unwritable() {
    let tmp = tempfile::tempdir().expect("make a temp dir");
    let log_dir = unwritable_log_dir(&tmp);

    let output = Command::new(env!("CARGO_BIN_EXE_diga"))
        .args(["--json", "profiles", "list"])
        .env("DIG_LOG_DIR", &log_dir)
        .output()
        .expect("spawn diga --json profiles list");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "stdout must be EXACTLY one JSON object (a logging warning must never land on \
             stdout); parse error: {e}; stdout was: {stdout}"
        )
    });
    assert!(
        parsed.is_object(),
        "stdout's one JSON value must be an object; got: {parsed}"
    );
}
