//! The OS-native, per-user byte channel underneath the CLI lane.
//!
//! # The permission model, which is the point of this module
//!
//! * **Unix** — the socket is bound inside the per-user brand data directory. That directory is set
//!   to `0700` BEFORE the bind and the socket file itself to `0600` immediately after, so a second
//!   local user can neither traverse to the socket nor `connect(2)` it. Unix checks write permission
//!   on the socket inode at connect time, which is what makes the mode load-bearing rather than
//!   decorative.
//! * **Windows** — the pipe is created under an explicit, protected, owner-only DACL built by
//!   [`crate::windows_security`]: one access-allowed entry for the calling user's SID and nothing
//!   else. [`bind`] creates the FIRST instance itself, with `FILE_FLAG_FIRST_PIPE_INSTANCE`, and
//!   the listener holds an unconnected instance from that moment until it is dropped — so the name
//!   is never unowned and a squatter is refused. The client opens with `SECURITY_IDENTIFICATION`,
//!   which lets a server identify it but never impersonate it.
//!
//! Both sides speak newline-delimited JSON, so the frame layer is
//! [`LineTransport`](dig_ipc_protocol::LineTransport) over the two halves of one duplex stream.

use std::io;
use std::path::Path;

use dig_ipc_protocol::LineTransport;

#[cfg(unix)]
pub use unix::{CliListener, CliStream};
#[cfg(windows)]
pub use windows_pipe::{CliListener, CliStream};

/// The frame transport a connected [`CliStream`] carries.
pub type CliFrames = LineTransport<CliStream, CliStream>;

/// Wrap a connected duplex stream in the newline-delimited frame transport.
///
/// The read half is a `try_clone`d handle of the same underlying object, so buffering the reader
/// cannot swallow bytes the writer still needs.
pub fn frames(stream: CliStream) -> io::Result<CliFrames> {
    let read_half = stream.try_clone()?;
    Ok(LineTransport::new(read_half, stream))
}

/// Connect to the CLI lane at `endpoint`, or report why not.
pub fn connect(endpoint: &str) -> io::Result<CliStream> {
    #[cfg(unix)]
    {
        unix::connect(endpoint)
    }
    #[cfg(windows)]
    {
        windows_pipe::connect(endpoint)
    }
}

/// Bind the CLI lane for the app rooted at `brand_dir`, at `endpoint`.
pub fn bind(endpoint: &str, brand_dir: &Path) -> io::Result<CliListener> {
    #[cfg(unix)]
    {
        unix::bind(endpoint, brand_dir)
    }
    #[cfg(windows)]
    {
        let _ = brand_dir;
        windows_pipe::bind(endpoint)
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!(
    "the dign CLI lane has no per-user channel on this target. A lane with no owner-only \
     transport would be reachable by every local process, so this is a build failure rather \
     than a silent downgrade."
);

#[cfg(unix)]
mod unix {
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    /// A connected CLI-lane stream.
    pub type CliStream = std::os::unix::net::UnixStream;

    /// The bound CLI-lane socket.
    pub struct CliListener(std::os::unix::net::UnixListener);

    impl CliListener {
        /// Block until a client connects.
        pub fn accept(&self) -> io::Result<CliStream> {
            self.0.accept().map(|(stream, _addr)| stream)
        }
    }

    /// Dial the socket at `endpoint`.
    pub fn connect(endpoint: &str) -> io::Result<CliStream> {
        CliStream::connect(endpoint)
    }

    /// Bind `endpoint`, tightening the containing directory first and the socket immediately after.
    ///
    /// A stale socket from a previous run is removed: `bind(2)` fails with `AddrInUse` on an existing
    /// path whether or not anything is listening on it, so an app that crashed would otherwise never
    /// serve the lane again.
    pub fn bind(endpoint: &str, brand_dir: &Path) -> io::Result<CliListener> {
        std::fs::create_dir_all(brand_dir)?;
        std::fs::set_permissions(brand_dir, std::fs::Permissions::from_mode(0o700))?;
        if Path::new(endpoint).exists() {
            std::fs::remove_file(endpoint)?;
        }
        let listener = std::os::unix::net::UnixListener::bind(endpoint)?;
        // The bind honours the process umask, which is not ours to assume. Restate the mode.
        std::fs::set_permissions(endpoint, std::fs::Permissions::from_mode(0o600))?;
        Ok(CliListener(listener))
    }
}

/// The Windows named-pipe transport.
///
/// # Why the name is claimed at BIND and never let go
///
/// A pipe name belongs to whoever creates its first instance, and it becomes unowned again the
/// moment the last instance closes. An earlier version of this module created every instance inside
/// `accept`, which left the name unclaimed before the first accept and again between every
/// conversation — and `dign` does not authenticate the server, sending the session token as its
/// first frame in cleartext. A local process that won either race would therefore harvest the token
/// and dictate everything `dign` prints, up to and including a wallet receive address.
///
/// So [`bind`] creates the first instance itself and [`CliListener`] holds an unconnected instance
/// at all times: `accept` connects the one it holds, mints its successor before returning, and
/// there is no window from bind onward in which the name is free. That also repairs the start-up
/// contract the rest of the lane already assumes — a squatted name now fails LOUDLY at bind, before
/// [`super::server::CliSessionServer`] publishes the token to disk, instead of failing at the first
/// accept with the token already written.
///
/// # Why the DACL is built rather than defaulted
///
/// `CreateNamedPipe`'s NULL security descriptor is documented to grant read access to **Everyone**
/// and to the **anonymous** account, which this host confirmed — so the "default DACL means this
/// user and SYSTEM" reading is simply wrong for a pipe. Any local user could open the pipe
/// read-only and never write, and the serial server would block in its untimed read for the app's
/// lifetime while every real `dign` invocation reported that dig-app was not running. The explicit
/// single-ACE DACL is what makes the per-user boundary in the module docs a fact instead of a claim.
#[cfg(windows)]
mod windows_pipe {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::Mutex;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
        SECURITY_IDENTIFICATION,
    };
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    use crate::windows_security::{ProtectedSecurity, PIPE_ALL_ACCESS};

    /// The per-instance pipe buffer. One frame is a line of JSON; the transport caps a frame at
    /// `dig_ipc_protocol`'s maximum, and this buffer is only a hint to the kernel.
    const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

    /// `ERROR_PIPE_CONNECTED` as an `HRESULT`-wrapped Win32 code: the client attached in the window
    /// between creating the instance and connecting it, which is a connection, not a failure.
    const HRESULT_PIPE_CONNECTED: u32 = 0x8007_00E8;

    /// A connected CLI-lane stream. A pipe handle IS a file handle, so `std::fs::File` is the whole
    /// implementation: it reads, writes, and duplicates for the two transport halves.
    pub type CliStream = std::fs::File;

    /// The bound CLI-lane pipe.
    ///
    /// Windows creates one pipe INSTANCE per client, and the name lives only as long as some
    /// instance does — so this listener always holds one that has been created and not yet
    /// connected. See the module docs for why that is a security property and not an optimisation.
    pub struct CliListener {
        name: Vec<u16>,
        security: ProtectedSecurity,
        /// The instance the next [`Self::accept`] will connect. Never `None` between accepts.
        pending: Mutex<Option<OwnedHandle>>,
    }

    impl CliListener {
        /// Block until a client connects, returning that client's pipe instance.
        pub fn accept(&self) -> io::Result<CliStream> {
            let instance = self.take_pending()?;
            connect_instance(&instance)?;

            // The successor is minted while the just-connected instance still holds the name, which
            // is what closes the between-conversations window: by the time this stream is handed
            // out and eventually dropped, another instance already owns the name.
            let successor = self.create_instance(false)?;
            *self.lock_pending()? = Some(successor);

            Ok(CliStream::from(instance))
        }

        /// Create one instance of this listener's name under its owner-only DACL.
        ///
        /// `first` passes `FILE_FLAG_FIRST_PIPE_INSTANCE`, which makes the call FAIL if the name is
        /// already owned rather than quietly joining a squatter's pipe as a second instance. Only
        /// [`bind`] may pass it: every later instance is an addition to a name we already hold, and
        /// the flag would refuse exactly that.
        fn create_instance(&self, first: bool) -> io::Result<OwnedHandle> {
            let attributes = self.security.attributes();
            // SAFETY: `name` is a NUL-terminated wide string owned by this listener for the
            // duration of the call, `attributes` borrows a descriptor that outlives it, and every
            // other argument is a plain flag value.
            let handle = unsafe {
                CreateNamedPipeW(
                    PCWSTR(self.name.as_ptr()),
                    open_mode(first),
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    PIPE_BUFFER_BYTES,
                    PIPE_BUFFER_BYTES,
                    0,
                    Some(&attributes),
                )
            };
            if handle.is_invalid() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `handle` is a valid, freshly created handle whose ownership moves here.
            Ok(unsafe { OwnedHandle::from_raw_handle(handle.0 as _) })
        }

        /// Take the instance the next client will be given.
        fn take_pending(&self) -> io::Result<OwnedHandle> {
            self.lock_pending()?.take().ok_or_else(|| {
                io::Error::other("the CLI lane holds no pipe instance to accept a client on")
            })
        }

        fn lock_pending(&self) -> io::Result<std::sync::MutexGuard<'_, Option<OwnedHandle>>> {
            self.pending
                .lock()
                .map_err(|_| io::Error::other("the CLI lane's pipe instance was lost to a panic"))
        }
    }

    /// The open mode for an instance: only the FIRST claims the name exclusively.
    fn open_mode(first: bool) -> FILE_FLAGS_AND_ATTRIBUTES {
        match first {
            true => PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            false => PIPE_ACCESS_DUPLEX,
        }
    }

    /// Block until a client attaches to `instance`.
    fn connect_instance(instance: &OwnedHandle) -> io::Result<()> {
        let handle = HANDLE(instance.as_raw_handle());
        // SAFETY: the handle is owned by `instance`, which outlives this call.
        match unsafe { ConnectNamedPipe(handle, None) } {
            Ok(()) => Ok(()),
            Err(e) if e.code().0 as u32 == HRESULT_PIPE_CONNECTED => Ok(()),
            Err(e) => Err(io::Error::other(format!("could not accept a client: {e}"))),
        }
    }

    /// Open the pipe at `endpoint`.
    ///
    /// `security_qos_flags(SECURITY_IDENTIFICATION)` bounds what the server may do with this client's
    /// token: identify it, never impersonate it. Without it a pipe server could act AS the user who
    /// ran `dign`.
    pub fn connect(endpoint: &str) -> io::Result<CliStream> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION.0)
            .open(endpoint)
    }

    /// Claim the pipe name at `endpoint`, creating and holding its first instance.
    ///
    /// Fails if anything already owns the name — which is the point: the caller has not yet
    /// published the session token, so a squatted lane is a loud start-up failure rather than a
    /// silent impersonation.
    pub fn bind(endpoint: &str) -> io::Result<CliListener> {
        let name: Vec<u16> = std::ffi::OsStr::new(endpoint)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let listener = CliListener {
            name,
            security: ProtectedSecurity::owner_only(PIPE_ALL_ACCESS)?,
            pending: Mutex::new(None),
        };
        let first = listener.create_instance(true)?;
        *listener.lock_pending()? = Some(first);
        Ok(listener)
    }

    #[cfg(test)]
    mod tests {
        use super::{bind, CliListener};
        use crate::windows_security::inspect::{anonymous, everyone, me, ObjectSecurity};
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            FILE_CREATE_PIPE_INSTANCE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        };

        /// A pipe name no other test or process is using.
        fn scratch_name() -> String {
            use std::sync::atomic::{AtomicU32, Ordering};
            static NEXT: AtomicU32 = AtomicU32::new(0);
            format!(
                r"\\.\pipe\dig-app-transport-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )
        }

        /// The DACL the OS actually recorded on the pipe grants the calling user and NOBODY else.
        ///
        /// The two named principals are not arbitrary: `CreateNamedPipe`'s DEFAULT descriptor — what
        /// this module used to pass — grants read access to exactly Everyone and ANONYMOUS LOGON, so
        /// they are the two the old code would fail on. Restoring `None` in `create_instance` turns
        /// this test red on the ACE count and on both effective-rights assertions.
        #[test]
        fn the_pipe_grants_its_owner_and_nobody_else() {
            let listener = bind(&scratch_name()).unwrap();
            let security = pipe_security(&listener);

            let dacl = security.dacl().unwrap();
            assert_eq!(
                dacl.entries, 1,
                "an owner-only pipe has exactly one access-allowed entry"
            );
            assert!(
                dacl.protected,
                "inheritance must be severed, or entries are merged back in"
            );

            for (who, name) in [
                (everyone().unwrap(), "Everyone"),
                (anonymous().unwrap(), "ANONYMOUS LOGON"),
            ] {
                assert_eq!(
                    security.rights_of(&who).unwrap(),
                    0,
                    "{name} must have no access at all to the CLI lane"
                );
            }

            // Deliberately NOT measured against `PIPE_ALL_ACCESS`: that is the mask this DACL was
            // BUILT from, so comparing the two only asserts that the OS stored what we asked for,
            // and stays green no matter how wrong the ask was. The independent yardstick is what a
            // real client requests -- `std::fs::OpenOptions.read(true).write(true)` becomes
            // `GENERIC_READ | GENERIC_WRITE`, which the OS expands to these two masks. An earlier
            // hand-enumerated `PIPE_ALL_ACCESS` omitted the EA bits inside them and denied every
            // `dign` connection; the circular version of this assertion passed throughout.
            let needed_by_a_client = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0;
            let mine = security.rights_of(&me().unwrap()).unwrap();
            assert_eq!(
                mine & needed_by_a_client,
                needed_by_a_client,
                "the owner must be granted everything opening the lane actually requires"
            );
            assert_eq!(
                mine & FILE_CREATE_PIPE_INSTANCE.0,
                FILE_CREATE_PIPE_INSTANCE.0,
                "the server must be able to mint the successor instance that holds the name"
            );
        }

        /// The name is owned from bind onward, so nothing can pre-claim or re-claim it.
        ///
        /// The second half is the one that matters: the old code released the name between
        /// conversations, so a squatter only had to wait for a client to disconnect. Binding again
        /// AFTER a full connect/serve/drop cycle is what distinguishes "held at start-up" from
        /// "held continuously" — a fix that only created the first instance in `bind` would pass the
        /// first assertion and fail this one.
        #[test]
        fn the_name_stays_claimed_across_a_conversation() {
            let name = scratch_name();
            let listener = bind(&name).unwrap();

            assert!(
                bind(&name).is_err(),
                "a second bind must be refused while we hold the name"
            );

            let client = std::thread::spawn({
                let name = name.clone();
                move || super::connect(&name)
            });
            let served = listener.accept().unwrap();
            client.join().unwrap().unwrap();
            drop(served);

            assert!(
                bind(&name).is_err(),
                "the name must still be ours after a conversation ends"
            );
        }

        /// Read the DACL of the instance the listener is currently holding.
        fn pipe_security(listener: &CliListener) -> ObjectSecurity {
            let pending = listener.pending.lock().unwrap();
            let instance = pending
                .as_ref()
                .expect("a bound listener holds an instance");
            ObjectSecurity::of_kernel_object(HANDLE(instance.as_raw_handle())).unwrap()
        }
    }
}
