//! The OS-native, per-user byte channel underneath the CLI lane.
//!
//! # The permission model, which is the point of this module
//!
//! * **Unix** — the socket is bound inside the per-user brand data directory. That directory is set
//!   to `0700` BEFORE the bind and the socket file itself to `0600` immediately after, so a second
//!   local user can neither traverse to the socket nor `connect(2)` it. Unix checks write permission
//!   on the socket inode at connect time, which is what makes the mode load-bearing rather than
//!   decorative.
//! * **Windows** — the pipe is created with a NULL security descriptor, which gives it the default
//!   DACL from this process's token: the interactive user and `SYSTEM`, and nobody else. The FIRST
//!   instance additionally passes `FILE_FLAG_FIRST_PIPE_INSTANCE`, so the listener FAILS if anything
//!   already owns the name instead of quietly joining a squatter's pipe as a second instance. The
//!   client opens with `SECURITY_IDENTIFICATION`, which lets a server identify it but never
//!   impersonate it.
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

#[cfg(windows)]
mod windows_pipe {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::FromRawHandle;
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
        SECURITY_IDENTIFICATION,
    };
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    /// The per-instance pipe buffer. One frame is a line of JSON; the transport caps a frame at
    /// `dig_ipc_protocol`'s maximum, and this buffer is only a hint to the kernel.
    const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

    /// `ERROR_PIPE_CONNECTED` as an `HRESULT`-wrapped Win32 code: the client attached in the window
    /// between creating the instance and connecting it, which is a connection, not a failure.
    const HRESULT_PIPE_CONNECTED: u32 = 0x8007_00E8;

    /// A connected CLI-lane stream. A pipe handle IS a file handle, so `std::fs::File` is the whole
    /// implementation: it reads, writes, and duplicates for the two transport halves.
    pub type CliStream = std::fs::File;

    /// The bound CLI-lane pipe. Windows creates one pipe INSTANCE per client, so the listener holds
    /// the name and mints an instance for each accept.
    pub struct CliListener {
        name: Vec<u16>,
        first_instance_taken: AtomicBool,
    }

    impl CliListener {
        /// Block until a client connects, returning that client's pipe instance.
        pub fn accept(&self) -> io::Result<CliStream> {
            // SAFETY: `name` is a NUL-terminated wide string owned by this listener for the duration
            // of the call, and every other argument is a plain flag value.
            let handle = unsafe {
                CreateNamedPipeW(
                    PCWSTR(self.name.as_ptr()),
                    self.open_mode(),
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    PIPE_BUFFER_BYTES,
                    PIPE_BUFFER_BYTES,
                    0,
                    // A NULL security descriptor gives the pipe this process token's DEFAULT DACL:
                    // the interactive user and SYSTEM. That is the per-user boundary, and it is
                    // stated by NOT passing a descriptor rather than by hand-building an ACL.
                    None,
                )
            };
            if handle.is_invalid() {
                return Err(io::Error::last_os_error());
            }
            self.first_instance_taken.store(true, Ordering::SeqCst);

            // SAFETY: `handle` is a valid pipe handle whose ownership moves into `stream`.
            let stream = unsafe { CliStream::from_raw_handle(handle.0 as _) };
            // SAFETY: the handle is owned by `stream`, which outlives this call.
            match unsafe { ConnectNamedPipe(handle, None) } {
                Ok(()) => Ok(stream),
                Err(e) if e.code().0 as u32 == HRESULT_PIPE_CONNECTED => Ok(stream),
                Err(e) => Err(io::Error::other(format!("could not accept a client: {e}"))),
            }
        }

        /// The open mode for the next instance: only the FIRST claims the name exclusively.
        fn open_mode(&self) -> FILE_FLAGS_AND_ATTRIBUTES {
            match self.first_instance_taken.load(Ordering::SeqCst) {
                true => PIPE_ACCESS_DUPLEX,
                false => PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            }
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

    /// Claim the pipe name at `endpoint`. No instance exists until the first accept.
    pub fn bind(endpoint: &str) -> io::Result<CliListener> {
        let name = std::ffi::OsStr::new(endpoint)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        Ok(CliListener {
            name,
            first_instance_taken: AtomicBool::new(false),
        })
    }
}
