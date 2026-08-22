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
//!   the crate's `windows_security` module: one access-allowed entry for the calling user's SID and
//!   nothing else. [`bind`] creates the FIRST instance itself, with `FILE_FLAG_FIRST_PIPE_INSTANCE`, and
//!   the listener holds an unconnected instance from that moment until it is dropped — so the name
//!   is never unowned and a squatter is refused. The client opens with `SECURITY_IDENTIFICATION`,
//!   which lets a server identify it but never impersonate it.
//!
//! Both sides speak newline-delimited JSON, so the frame layer is
//! [`dig_ipc_protocol::LineTransport`] over the two halves of one duplex stream.

use std::io;
use std::path::Path;

use dig_ipc_protocol::LineTransport;

use super::deadline::{DeadlineReader, FrameBudget};

#[cfg(unix)]
pub use unix::{CliListener, CliStream};
#[cfg(windows)]
pub use windows_pipe::{CliListener, CliStream};

/// The frame transport a connected [`CliStream`] carries.
///
/// The read half is wrapped in a [`DeadlineReader`], which is what stops a peer that accepted the
/// connection and then went silent from blocking this process forever.
pub type CliFrames = LineTransport<DeadlineReader<CliStream>, CliStream>;

/// Wrap a connected duplex stream in the newline-delimited frame transport, bounding every frame read
/// from it by `budget`.
///
/// The read half is a `try_clone`d handle of the same underlying object, so buffering the reader
/// cannot swallow bytes the writer still needs.
///
/// # Why the WRITE half is bounded only on Unix
///
/// A write to a peer that never reads blocks once the kernel buffer fills, so it wants a bound too,
/// and Unix has one: `SO_SNDTIMEO`. Windows has no write timeout for a synchronous pipe handle, and
/// the leg is far less exposed than the read — every frame this lane writes is a single line of JSON,
/// orders of magnitude below the pipe's own 64 KiB buffer, so a write completes into that buffer
/// whether or not the peer ever reads it. The unbounded case is a frame larger than the buffer, which
/// this protocol does not produce.
pub fn frames(stream: CliStream, budget: FrameBudget) -> io::Result<CliFrames> {
    let read_half = stream.try_clone()?;
    #[cfg(unix)]
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    Ok(LineTransport::new(
        DeadlineReader::new(read_half, budget),
        stream,
    ))
}

/// The longest a single frame write may block before it is reported as a failed lane.
///
/// Generous on purpose: it bounds a pathological peer, and is not a latency budget. Unix only — see
/// [`frames`].
#[cfg(unix)]
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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

    use windows::core::{HRESULT, PCWSTR};
    use windows::Win32::Foundation::{ERROR_PIPE_CONNECTED, HANDLE};
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

    /// `ERROR_PIPE_CONNECTED` as the `HRESULT` `ConnectNamedPipe` reports it through: the client
    /// attached in the window between creating the instance and connecting it, which is a
    /// connection, not a failure.
    ///
    /// DERIVED from the `windows` crate's own named constant, never hand-written. This line used to
    /// be the literal `0x8007_00E8`, which names 232 (`ERROR_NO_DATA`) and not 535
    /// (`ERROR_PIPE_CONNECTED`) -- so the ordinary connect race was misclassified as an accept
    /// failure and `client::tests::a_real_client_reaches_a_real_server_over_the_per_user_channel`
    /// failed three runs in eight. A value that cannot be typed cannot be mistyped;
    /// `tests::the_connect_race_is_recognised_by_its_named_win32_code` pins it against the crate
    /// constant so a future hand-edit cannot silently re-break it.
    fn pipe_connected() -> HRESULT {
        ERROR_PIPE_CONNECTED.to_hresult()
    }

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
        ///
        /// # Why every failure arm leaves the lane able to accept again
        ///
        /// An earlier version took the pending instance and returned on the first error, which left
        /// `pending` empty with nothing re-minting it: the lane was then PERMANENTLY unable to
        /// accept, so one transient fault read to the user as "dig-app is not running" for the whole
        /// life of a running app. The retry ceiling in
        /// `super::server` cannot recover from that, because retrying an accept that can no longer
        /// hold an instance just burns the ceiling.
        ///
        /// So a failed `ConnectNamedPipe` puts its still-unconnected instance BACK -- the name never
        /// goes unowned and the next attempt reuses it -- and a failed successor mint leaves the
        /// reclaim to `Self::take_pending`. Neither arm loosens the ceiling: a lane that keeps
        /// failing still gives up after `MAX_CONSECUTIVE_ACCEPT_FAULTS`, it simply is no longer
        /// guaranteed to fail.
        pub fn accept(&self) -> io::Result<CliStream> {
            let instance = self.take_pending()?;
            if let Err(e) = connect_instance(&instance) {
                // The instance was never connected, so it is still a usable listening instance and
                // still holds the name. Returning without it is what killed the lane.
                *self.lock_pending()? = Some(instance);
                return Err(e);
            }

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

        /// Take the instance the next client will be given, re-claiming the name if a previous
        /// failure left the lane holding none.
        ///
        /// The reclaim passes `first`, which is the security-preserving choice rather than a
        /// convenience: if the name is genuinely free we take it back EXCLUSIVELY, and if anything
        /// else has claimed it in the meantime `CreateNamedPipeW` fails loudly instead of joining
        /// the squatter's pipe as a second instance. Minting without the flag here would hand the
        /// next `dign` -- which sends its session token as its first frame -- to whoever won that
        /// race.
        fn take_pending(&self) -> io::Result<OwnedHandle> {
            match self.lock_pending()?.take() {
                Some(instance) => Ok(instance),
                None => self.create_instance(true),
            }
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
            Err(e) if e.code() == pipe_connected() => Ok(()),
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

        /// A second `dign` arriving MID-CONVERSATION connects instead of being told the app is not
        /// running.
        ///
        /// This is the user-visible half of holding the name continuously. Windows has no listen
        /// backlog: a client whose `connect` finds no unconnected instance gets
        /// `ERROR_FILE_NOT_FOUND`, which the client layer maps to `NOT_CONNECTED` -- "dig-app is not
        /// running" -- about an app that is running and busy. Unix does not have this because the
        /// `UnixListener` backlog queues the second client, so a scripted loop over `dign` was
        /// intermittently lied to on Windows only.
        ///
        /// The fixture is deliberately the BUSY case rather than the idle one: the first client is
        /// accepted and deliberately NOT dropped, so the successor instance is the only thing the
        /// second client can attach to. An implementation that minted the successor lazily -- at the
        /// next `accept` rather than during the current one -- serves the idle case identically and
        /// fails exactly here.
        #[test]
        fn a_second_client_connects_while_the_first_is_still_being_served() {
            let name = scratch_name();
            let listener = bind(&name).unwrap();

            let first = std::thread::spawn({
                let name = name.clone();
                move || super::connect(&name)
            });
            let serving = listener.accept().unwrap();
            first.join().unwrap().unwrap();

            // `serving` is still open: the lane is mid-conversation, which is exactly when the old
            // code had no instance listening.
            let second = super::connect(&name);
            assert!(
                second.is_ok(),
                "a client arriving mid-conversation must queue, not be told the app is absent: {:?}",
                second.err()
            );

            drop(serving);
        }

        /// The connect race is recognised by the crate's OWN named code, not by a hand-typed hex.
        ///
        /// Both halves are load-bearing. `ERROR_PIPE_CONNECTED` is 535 (`0x217`), so the `HRESULT`
        /// the pipe API reports is `0x8007_0217`; the literal this module shipped, `0x8007_00E8`,
        /// wraps 232 (`ERROR_NO_DATA`) instead, and under it a client that attached a microsecond
        /// early was reported to the user as "could not accept a client". Pinning the derived value
        /// against the crate constant AND against the number means a future hand-edit back to a
        /// literal fails here rather than three runs in eight somewhere else.
        #[test]
        fn the_connect_race_is_recognised_by_its_named_win32_code() {
            use windows::core::HRESULT;
            use windows::Win32::Foundation::ERROR_PIPE_CONNECTED;

            assert_eq!(
                ERROR_PIPE_CONNECTED.0, 535,
                "the Win32 code this arm names is 535; 232 is ERROR_NO_DATA"
            );
            assert_eq!(
                super::pipe_connected(),
                ERROR_PIPE_CONNECTED.to_hresult(),
                "the tolerated HRESULT must be derived from the named constant"
            );
            assert_eq!(
                super::pipe_connected(),
                HRESULT(0x8007_0217_u32 as i32),
                "ERROR_PIPE_CONNECTED wrapped as an HRESULT is 0x80070217"
            );
        }

        /// A lane that has already suffered an accept fault can still accept a client.
        ///
        /// The fixture reproduces the exact state every error arm used to leave behind -- `pending`
        /// empty -- and then asks the lane to do its job. Against the old code the second and third
        /// `accept` both returned "the CLI lane holds no pipe instance to accept a client on",
        /// permanently, so a single transient fault made a running app indistinguishable from an
        /// absent one. A control client is served BEFORE the fault is injected, so the test cannot
        /// pass by the lane being broken in some other way.
        #[test]
        fn the_lane_still_accepts_after_a_fault_emptied_its_pending_instance() {
            let name = scratch_name();
            let listener = bind(&name).unwrap();

            serve_one_client(&listener, &name);

            // The fault: the instance is gone and nothing re-minted it.
            drop(listener.pending.lock().unwrap().take().expect("bound"));

            serve_one_client(&listener, &name);
            // Twice, because a recovery that works exactly once is the same defect one accept later.
            serve_one_client(&listener, &name);
        }

        /// Re-claiming after a fault must REFUSE a name someone else now owns.
        ///
        /// Recovery is only safe because the reclaim keeps `FILE_FLAG_FIRST_PIPE_INSTANCE`. Without
        /// it the lane would happily add an instance to a squatter's pipe and hand the next `dign`
        /// -- whose first frame is the session token in cleartext -- to that squatter. The squatter
        /// here is a second `bind` of the same name, which is only possible in the post-fault window
        /// this test creates.
        #[test]
        fn a_squatted_name_is_refused_rather_than_joined_when_reclaiming() {
            let name = scratch_name();
            let listener = bind(&name).unwrap();
            drop(listener.pending.lock().unwrap().take().expect("bound"));

            let squatter = bind(&name).expect("the name is free in the post-fault window");

            let refusal = listener
                .take_pending()
                .expect_err("reclaiming a name another process owns must fail, not join its pipe");
            // The refusal must come from `CreateNamedPipeW` refusing the name, NOT from the lane
            // having given up on reclaiming at all: a listener that simply reports "no instance"
            // satisfies `is_err()` while proving nothing about the flag this test exists for.
            assert!(
                refusal.raw_os_error().is_some(),
                "the refusal must be the OS refusing the squatted name, got: {refusal:?}"
            );

            drop(squatter);
        }

        /// Connect a client and serve it, asserting both halves succeeded.
        fn serve_one_client(listener: &CliListener, name: &str) {
            let client = std::thread::spawn({
                let name = name.to_string();
                move || super::connect(&name)
            });
            let served = listener
                .accept()
                .expect("the lane must accept a client whenever one is dialling");
            client.join().unwrap().unwrap();
            drop(served);
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
