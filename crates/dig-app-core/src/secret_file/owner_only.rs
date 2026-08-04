//! Put a secret on disk readable by its owner ALONE, on every platform we ship.

use std::io;
use std::path::Path;

/// Write `bytes` to `path` so that only the calling user can read them back.
///
/// # Why this is not `fs::write` plus a permission call
///
/// The naive shape — write the file, then tighten it — creates the file at the platform default
/// and only narrows it AFTERWARDS. Between those two calls the secret is already on disk at the
/// looser permission, and a colocated unprivileged process only has to be reading the directory to
/// catch it (dig_ecosystem#1564). So the restriction is applied at CREATION here, and a
/// pre-existing file is re-tightened while it is still truncated and empty — before any secret
/// byte is written, in both cases.
///
/// # What "owner-only" means per platform
///
/// * **Unix** — mode `0600`, passed to `open(2)` so it is the mode the file is created with.
/// * **Windows** — an explicit, PROTECTED DACL holding a single access-allowed ACE for the calling
///   user's own SID. Windows does not honour mode bits at all, so this is not a translation of
///   `0600` but the genuine equivalent; the `windows_acl` module documents why the profile
///   directory's inherited ACLs are not good enough (dig_ecosystem#1965).
///
/// Any other target fails to COMPILE rather than silently writing a secret at the platform
/// default — a file this function returns `Ok(())` for must really be owner-only.
///
/// # Errors
///
/// Returns the underlying I/O error if the file cannot be created, cannot be restricted, or cannot
/// be written. A failure to RESTRICT is an error like any other, so a caller that only checks for
/// `Ok` can never end up with a written-but-unprotected secret.
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        unix_write_owner_only(path, bytes)
    }
    #[cfg(windows)]
    {
        super::windows_acl::write_owner_only(path, bytes)
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!(
    "write_owner_only has no owner-only implementation for this target. A secret must never be \
     written at the platform default, so this is a build failure rather than a silent downgrade."
);

/// Create-or-truncate `path` at mode `0600` and write `bytes` into it.
#[cfg(unix)]
fn unix_write_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    write_at_mode_600(path, bytes, |file| {
        Ok(file.metadata()?.permissions().mode() & 0o777)
    })
}

/// The body of [`unix_write_owner_only`], with the mode read-back injected.
///
/// # Why the mode is READ BACK rather than assumed
///
/// `mode()` applies only when the file is CREATED, so a pre-existing (perhaps `0644`) file keeps its
/// old mode — hence the explicit tighten, done while the file is open and truncated to zero length,
/// so it holds no secret to leak at the looser mode.
///
/// Neither step is enough on its own, because **not every filesystem stores a mode**. A FAT/exFAT
/// volume — the removable disk this feature's save picker exists to enable — either rejects the
/// change (`EPERM`, caught by `?`) or, worse, *accepts it and does nothing*: `chmod` on macOS
/// `msdosfs` is a silent no-op. That second case would return `Ok(())` for a file that is not
/// owner-only, which is precisely what this function's contract says can never happen.
///
/// So the mode is verified after being set. Anything other than `0600` fails the backup — the caller
/// reports that the backup did not complete, and the user picks a destination that can hold a secret.
/// This is deliberately STRICTER than the Windows arm, which detects an ACL-less volume and proceeds:
/// the equivalent capability question on Unix (`statfs` filesystem-magic matching) is per-OS, has no
/// portable spelling, and cannot be exercised on any CI runner, so refusing is the honest behaviour
/// until it can be answered properly. SPEC §3.1a records that asymmetry as intentional.
#[cfg(unix)]
fn write_at_mode_600(
    path: &Path,
    bytes: &[u8],
    mode_of: impl Fn(&std::fs::File) -> io::Result<u32>,
) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;

    let mode = mode_of(&file)?;
    if mode != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("this location cannot restrict the file to its owner (mode {mode:o})"),
        ));
    }
    file.write_all(bytes)
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::{write_at_mode_600, write_owner_only};
    use std::io;
    use std::os::unix::fs::PermissionsExt;

    /// A destination that cannot actually hold the mode is a FAILED backup, never a quiet success.
    ///
    /// This is the case a `chmod` that returns `Ok` while changing nothing produces — macOS
    /// `msdosfs` on a FAT stick, the destination the save picker exists to enable. Without the
    /// read-back the function would report success for a file anyone can read, which is the one
    /// thing its contract promises it will never do.
    #[test]
    fn a_volume_that_ignores_the_mode_fails_the_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");

        // A filesystem whose chmod is a no-op: the call succeeded, the mode did not change.
        let error = write_at_mode_600(&path, b"redacted\n", |_| Ok(0o644)).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"",
            "the secret must not be written to a file that could not be restricted"
        );
    }

    /// The read-back accepts the mode it asked for, so the check cannot reject every write.
    #[test]
    fn a_volume_that_honours_the_mode_completes_the_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");

        write_at_mode_600(&path, b"redacted\n", |_| Ok(0o600)).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"redacted\n");
    }

    /// A new secret file is CREATED owner-only, never at the umask default and tightened after.
    #[test]
    fn a_new_secret_file_is_created_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");

        write_owner_only(&path, b"never printed\n").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file must be 0600, was {mode:o}");
        assert_eq!(mode & 0o077, 0, "group and other must hold no bits at all");
    }

    /// A pre-existing world-readable file is tightened while still empty (truncated), BEFORE the
    /// secret lands — so the secret never sits on disk at the old mode.
    #[test]
    fn a_preexisting_loose_file_is_tightened_before_the_secret_lands() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, b"stale content").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_owner_only(&path, b"replacement\n").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "pre-existing file must end 0600, was {mode:o}");
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement\n");
    }

    /// An unwritable destination is reported as an error rather than swallowed — the caller turns
    /// that into "the backup did not complete" instead of telling the user their words are safe.
    #[test]
    fn an_unwritable_destination_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-such-subdir").join("secret.txt");

        assert!(write_owner_only(&path, b"never written\n").is_err());
    }
}

/// The Windows permission tests, which ask the OS what the file's ACL actually GRANTS.
///
/// # Why they are shaped like this
///
/// A permission test that merely runs as the file's owner proves nothing: the owner can read the
/// file under every ACL there is, including the wrong one. So none of these tests read the file.
/// They ask the security reference monitor what rights OTHER principals — Everyone, the local
/// Administrators group — have against the ACL that ended up on disk, which is the same evaluation
/// an actual second user's open call would go through.
///
/// The first test also asserts a CONTROL: an ordinary `fs::write` in the same directory must hand
/// some non-owner principal real rights. Without that, a directory that happened to be narrow
/// already would make every assertion below pass while proving nothing.
#[cfg(all(test, windows))]
mod windows_tests {
    use super::write_owner_only;
    use crate::secret_file::windows_acl::inspect::{
        administrators, everyone, me, open_to_everyone, readable_without_owner_sid, system,
        FileSecurity,
    };
    use windows::Win32::Storage::FileSystem::FILE_GENERIC_READ;

    /// The secret is readable by its owner and by nobody else — not Everyone, not Administrators,
    /// not SYSTEM.
    #[test]
    fn no_principal_but_the_owner_is_granted_access() {
        let dir = tempfile::tempdir().unwrap();
        let administrators = administrators().unwrap();
        let system = system().unwrap();

        // CONTROL. An ordinary file in this very directory inherits rights for principals that are
        // not its owner. If it does not, the environment is not the one this test reasons about and
        // the assertions below would be vacuous — so fail here, loudly, rather than pass falsely.
        let ordinary = dir.path().join("ordinary.txt");
        std::fs::write(&ordinary, b"not a secret").unwrap();
        let inherited = FileSecurity::of(&ordinary).unwrap();
        assert!(
            inherited.rights_of(&administrators).unwrap() != 0
                || inherited.rights_of(&system).unwrap() != 0,
            "control failed: a plain write here already grants no non-owner principal anything, so \
             this test cannot tell an owner-only ACL from an inherited one"
        );

        // SUBJECT.
        let secret = dir.path().join("secret.txt");
        write_owner_only(&secret, b"redacted\n").unwrap();
        let security = FileSecurity::of(&secret).unwrap();

        for (who, name) in [
            (&administrators, "Administrators"),
            (&system, "SYSTEM"),
            (&everyone().unwrap(), "Everyone"),
        ] {
            assert_eq!(
                security.rights_of(who).unwrap(),
                0,
                "{name} must be granted nothing on a recovery-phrase file"
            );
        }

        let mine = security.rights_of(&me().unwrap()).unwrap();
        assert_eq!(
            mine & FILE_GENERIC_READ.0,
            FILE_GENERIC_READ.0,
            "the owner must keep read access, or the backup is unreadable to the user who made it"
        );
    }

    /// A principal that is not the owner cannot OPEN the file — the real syscall, not an ACL query.
    ///
    /// The tests above ask the OS to evaluate the ACL. This one performs the access check itself, on
    /// a thread whose token has the owner's SID marked deny-only, so the single allow-ACE grants it
    /// nothing. It is the check an owner-run test cannot make, and the class of check that catches a
    /// permission bug a whole suite of owner-run scenarios will happily miss.
    ///
    /// Two controls, because one is not enough to make the denial mean anything:
    ///
    /// 1. A file granted to Everyone must be READABLE through the restricted token — otherwise the
    ///    probe denies everything and would "prove" any file secure.
    /// 2. A plain `fs::write` file must be readable too. That is the before-state the subject is
    ///    compared against; without it the test passes against a reverted implementation, since a
    ///    non-elevated token reaches an inherited-ACL file by no route either. It only holds when
    ///    elevated, so where it cannot be established the test skips rather than bank an unearned
    ///    pass — and on CI, where the runner IS elevated, failing to establish it is an error.
    #[test]
    fn a_principal_without_the_owner_sid_cannot_open_the_file() {
        let dir = tempfile::tempdir().unwrap();

        // CONTROL 1 — the probe can read something. Everyone is enabled in the restricted token.
        let shared = dir.path().join("shared.txt");
        std::fs::write(&shared, b"not a secret").unwrap();
        open_to_everyone(&shared).unwrap();
        assert!(
            readable_without_owner_sid(&shared).unwrap(),
            "control failed: the probe cannot read even a world-readable file, so it would call \
             any file protected"
        );

        // CONTROL 2 — the probe can read the BEFORE-state. Without this the comparison is empty.
        let ordinary = dir.path().join("ordinary.txt");
        std::fs::write(&ordinary, b"not a secret").unwrap();
        if !readable_without_owner_sid(&ordinary).unwrap() {
            // On CI this is a FAILURE, not a skip. The runner is elevated, so the control is
            // expected to hold there — and `cargo test` captures the output of a PASSING test, so a
            // skip would be invisible in the log and the suite would look like it proved something
            // it never ran. Making CI insist on it is the only way the green tick means anything.
            assert!(
                std::env::var_os("CI").is_none(),
                "the cross-principal probe cannot discriminate on CI, where it is required to: an \
                 inherited-ACL file was already unreadable without the owner SID, so this test \
                 would pass without testing anything"
            );
            eprintln!(
                "SKIPPED a_principal_without_the_owner_sid_cannot_open_the_file: an inherited-ACL \
                 file is already unreadable without the owner SID in this session, so the probe \
                 cannot distinguish the fix from the defect. Requires an elevated session."
            );
            return;
        }

        // SUBJECT — the same probe, against the recovery-phrase file.
        let secret = dir.path().join("secret.txt");
        write_owner_only(&secret, b"redacted\n").unwrap();

        assert!(
            !readable_without_owner_sid(&secret).unwrap(),
            "a principal other than the owner opened the recovery-phrase file"
        );
    }

    /// The list is PROTECTED and holds exactly one entry — the Windows spelling of `0600`.
    ///
    /// Protection is the load-bearing half: an unprotected single-entry list has the parent
    /// directory's inheritable entries merged back into it and stops being owner-only.
    #[test]
    fn the_dacl_is_protected_and_holds_a_single_entry() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret.txt");

        write_owner_only(&secret, b"redacted\n").unwrap();

        let dacl = FileSecurity::of(&secret).unwrap().dacl().unwrap();
        assert!(
            dacl.protected,
            "the DACL must be protected, or the profile's inheritable entries merge back in"
        );
        assert_eq!(
            dacl.entries, 1,
            "owner-only means exactly one entry, found {}",
            dacl.entries
        );
    }

    /// A pre-existing world-readable file has that access REMOVED before the secret is written.
    ///
    /// This is the case `CreateFileW`'s security descriptor silently skips: for a path that already
    /// exists, `CREATE_ALWAYS` truncates and ignores the descriptor. Without the second, explicit
    /// application to the open handle, the secret would land under the old wide ACL.
    #[test]
    fn a_preexisting_world_readable_file_is_narrowed_before_the_secret_lands() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret.txt");
        std::fs::write(&secret, b"stale content").unwrap();
        open_to_everyone(&secret).unwrap();

        // The starting condition is asserted, not assumed: the point of the test is the TRANSITION.
        let everyone = everyone().unwrap();
        let before = FileSecurity::of(&secret)
            .unwrap()
            .rights_of(&everyone)
            .unwrap();
        assert_ne!(before, 0, "setup failed: Everyone was never granted access");

        write_owner_only(&secret, b"redacted\n").unwrap();

        let security = FileSecurity::of(&secret).unwrap();
        assert_eq!(
            security.rights_of(&everyone).unwrap(),
            0,
            "the pre-existing world-readable grant must be gone once the secret is on disk"
        );
        assert_eq!(security.dacl().unwrap().entries, 1);
        assert_eq!(std::fs::read(&secret).unwrap(), b"redacted\n");
    }
}
