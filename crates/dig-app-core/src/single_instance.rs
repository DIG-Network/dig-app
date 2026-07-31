//! One dig-app per user, enforced by the OS rather than by hope (dig_ecosystem#1831).
//!
//! dig-app is a tray agent people start by *not thinking about it*: the installer launches it when it
//! finishes, the OS launches it again at the next login, and a user who cannot see a tray icon will
//! happily double-click the binary a third time. Before this module none of those were guarded, so a
//! second copy simply ran: two tray icons, two agents reconciling the same profile directory, and a
//! second APP-SIGN server that lost the race for port 9779 and logged the loss at `error` while
//! staying alive — a broken agent that *looks* installed.
//!
//! # Why an OS file lock, and not the obvious alternatives
//!
//! * **A PID file** has to be reaped: a crash or a `kill -9` leaves one behind, and the "is that pid
//!   still alive?" check races pid reuse. This lock is held by an open file DESCRIPTOR, so the kernel
//!   drops it when the process dies however it dies — there is no stale state to reason about.
//! * **A bound port** cannot answer the question here. dig-app boots with the account LOCKED
//!   (dig_ecosystem#1817), so the APP-SIGN listener does not exist until the user unlocks; a port-based
//!   guard would be blind for the whole locked window, which is exactly when a login autostart fires.
//! * **A machine-global named mutex** would be *too* exclusive: dig-app is a per-USER agent, and two
//!   accounts logged into the same box are two legitimate instances. The lock is therefore scoped to
//!   the brand directory, which is already per-user.
//!
//! # The per-OS primitive
//!
//! * **Unix** — `flock(LOCK_EX | LOCK_NB)`. The lock belongs to the open file description, so a second
//!   `open` in the same process contends exactly as a second process does; that is what lets the tests
//!   below exercise the real contention path rather than a simulation of it.
//! * **Windows** — the file is opened with a share mode of zero, so a second `CreateFile` on it fails
//!   with a sharing violation. Same ownership semantics: the handle, and therefore the exclusion, is
//!   released by the kernel when the process exits.
//!
//! Both leave the lock FILE on disk between runs. That is deliberate and is the property the tests
//! pin: the file existing means nothing, only the lock on it does, so a crashed instance never locks
//! the user out of their own agent.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// The lock file's name inside the brand directory. Stable, so a support answer to "is dig-app
/// running?" names one path on every platform.
pub const LOCK_FILE_NAME: &str = "dig-app.lock";

/// The lock file for the dig-app instance owning `brand_dir`.
pub fn lock_path(brand_dir: &Path) -> PathBuf {
    brand_dir.join(LOCK_FILE_NAME)
}

/// The result of asking to be *the* dig-app for a brand directory.
///
/// Not a `Result`: "another instance already has it" is a normal, expected answer — it is what every
/// duplicate launch this module exists to absorb looks like — whereas an `io::Error` means the lock
/// could not be evaluated at all.
#[derive(Debug)]
pub enum Acquired {
    /// This process is now the single instance; the lock lives until the guard is dropped.
    Yes(InstanceLock),
    /// Another live process holds the lock. Nothing was changed.
    AlreadyRunning,
}

/// Proof that this process is the only dig-app for one brand directory, for as long as it is held.
///
/// Dropping it (or exiting, however abruptly) releases the lock. There is no `unlock` method: the only
/// correct lifetime is "until this process stops being dig-app", which is what a guard expresses and a
/// method invites callers to get wrong.
#[derive(Debug)]
pub struct InstanceLock {
    /// The locked handle. Never read or written — the file's CONTENT carries no meaning, only the
    /// kernel lock on it does, which is what makes a leftover file from a crashed run harmless.
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    /// The file this lock is held on, for logs and support questions.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Take the single-instance lock for `brand_dir`, creating the directory and the lock file if needed.
///
/// Returns [`Acquired::AlreadyRunning`] when another live dig-app holds it. An `Err` means the lock
/// could not be evaluated (an unreadable directory, a full disk) — callers must NOT treat that as
/// "nobody else is running", because failing open would reintroduce the duplicate instance this
/// module removes.
pub fn acquire(brand_dir: &Path) -> io::Result<Acquired> {
    std::fs::create_dir_all(brand_dir)?;
    let path = lock_path(brand_dir);
    match open_exclusive(&path) {
        Ok(Some(file)) => Ok(Acquired::Yes(InstanceLock { _file: file, path })),
        Ok(None) => Ok(Acquired::AlreadyRunning),
        Err(e) => Err(e),
    }
}

/// Open `path` holding an exclusive OS lock, or `Ok(None)` if another process already holds one.
#[cfg(unix)]
fn open_exclusive(path: &Path) -> io::Result<Option<File>> {
    use std::os::unix::io::AsRawFd;

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    // SAFETY: `flock` is called with a descriptor this function owns and a valid operation constant;
    // it neither reads nor writes user memory.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if locked == 0 {
        return Ok(Some(file));
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        // Both spellings of "someone else holds it" — they are the same value on Linux but distinct
        // on some BSDs, so both are matched rather than assuming the platform this was written on.
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => Ok(None),
        _ => Err(e),
    }
}

/// Windows: a share mode of zero makes the open itself the exclusion.
#[cfg(windows)]
fn open_exclusive(path: &Path) -> io::Result<Option<File>> {
    use std::os::windows::fs::OpenOptionsExt;

    /// `dwShareMode = 0` — no other process may open this file for read, write, or delete while this
    /// handle is alive.
    const NO_SHARING: u32 = 0;
    /// `ERROR_SHARING_VIOLATION` — the live-instance answer, not a failure to evaluate the lock.
    const ERROR_SHARING_VIOLATION: i32 = 32;

    match OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .share_mode(NO_SHARING)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hold(dir: &Path) -> InstanceLock {
        match acquire(dir).expect("the lock is evaluable") {
            Acquired::Yes(lock) => lock,
            Acquired::AlreadyRunning => panic!("nothing else should hold {}", dir.display()),
        }
    }

    fn is_already_running(dir: &Path) -> bool {
        matches!(
            acquire(dir).expect("the lock is evaluable"),
            Acquired::AlreadyRunning
        )
    }

    /// THE property: while one instance holds the lock, a second attempt is refused.
    ///
    /// The second `acquire` opens its own descriptor, which on both platforms contends with the first
    /// exactly as a separate process would — so this exercises the real kernel exclusion rather than a
    /// bookkeeping flag the same process could see.
    #[test]
    fn a_second_acquire_is_refused_while_the_first_is_held() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = hold(tmp.path());
        assert!(
            is_already_running(tmp.path()),
            "a second dig-app must be told another instance owns {}",
            first.path().display()
        );
    }

    /// The stale-lock property, and the reason this is a kernel lock rather than a file-exists check.
    ///
    /// The nearest wrong implementation — "if the lock file is present, someone is running" — passes
    /// the test above and fails here: the file deliberately SURVIVES the release (asserted, so the
    /// fixture cannot be satisfied by an implementation that simply deletes it and calls that a
    /// release), yet the next instance must still be able to start. A user whose dig-app was killed
    /// must not be locked out of their own agent until they find and delete a file.
    #[test]
    fn releasing_the_lock_lets_the_next_instance_start_even_though_the_file_remains() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = hold(tmp.path());
        let path = first.path().to_path_buf();
        drop(first);

        assert!(
            path.exists(),
            "the lock file is expected to outlive the lock — otherwise this test proves nothing \
             about staleness"
        );
        let second = hold(tmp.path());
        assert_eq!(second.path(), path);
    }

    /// The lock is per-USER, not per-machine.
    ///
    /// Two accounts logged into one box are two legitimate dig-apps. The nearest wrong implementation
    /// is a machine-global named mutex, which passes every test above and fails this one by letting
    /// the first user to log in block the second out of their own identity agent. Both locks are held
    /// SIMULTANEOUSLY here, which is the only arrangement that can observe the difference.
    #[test]
    fn two_brand_directories_are_two_independent_instances() {
        let alice = tempfile::tempdir().expect("tempdir");
        let bob = tempfile::tempdir().expect("tempdir");
        let _alice_lock = hold(alice.path());
        let _bob_lock = hold(bob.path());
    }

    /// A first run has no brand directory yet; the login autostart must not be the thing that fails
    /// because of it.
    #[test]
    fn acquiring_creates_a_brand_directory_that_does_not_exist_yet() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let fresh = tmp.path().join("never").join("created");
        assert!(!fresh.exists());

        let lock = hold(&fresh);
        assert_eq!(lock.path(), lock_path(&fresh));
        assert!(fresh.is_dir());
    }

    #[test]
    fn the_lock_file_lives_inside_the_brand_directory_under_a_stable_name() {
        let dir = Path::new("/home/alice/.dig");
        assert_eq!(lock_path(dir), dir.join("dig-app.lock"));
        assert_eq!(LOCK_FILE_NAME, "dig-app.lock");
    }
}
