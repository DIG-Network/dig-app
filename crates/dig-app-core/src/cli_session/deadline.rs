//! Read deadlines for the CLI lane, so a peer that accepts and then says nothing cannot stop `dign`
//! from ever returning.
//!
//! # The failure this exists to remove
//!
//! The lane's endpoint address is derived from the login name and needs no privilege to claim, so the
//! peer on the other side of a successful `connect` is not necessarily dig-app (proving that is what
//! [`super::client`]'s server challenge is for). Before this module nothing on the lane had a
//! deadline: a peer that completed the accept and then never wrote left `recv_frame` blocked in the
//! kernel for as long as it cared to stay silent. That is not a crash and not a refusal — it is a
//! terminal that has stopped, with no error, no exit and nothing to report. It does not even need to
//! be hostile; a wedged process holding the pipe does the same thing.
//!
//! # Why the deadline lives under the frame layer rather than in it
//!
//! [`DeadlineReader`] is the reader half [`super::transport::frames`] hands to
//! [`LineTransport`](dig_ipc_protocol::LineTransport), which buffers it. Sitting BELOW that buffer is
//! what makes the bound correct: the buffer only calls [`Read::read`] when it genuinely needs more
//! bytes from the peer, so a deadline here can never fire on a frame that has already arrived.
//!
//! # Why the deadline is per FRAME, and armed by the reader itself
//!
//! A budget re-armed on every `read` call would bound each syscall and nothing else — a peer that
//! dribbles one byte per interval would still hold the lane forever. So the deadline is ABSOLUTE and
//! spans a whole frame, including the framed-length read inside it: it is armed on the first read
//! after a frame boundary and disarmed by the newline that ends one. The reader can do that alone
//! because the newline IS the framing, which is why no caller has to remember to arm anything.

use std::io::{self, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The longest a single blocking wait may last before the remaining budget is re-checked.
///
/// A ceiling, never the deadline: it exists so a platform whose wait cannot be interrupted still
/// returns to this module often enough to notice the deadline has passed.
const WAIT_SLICE: Duration = Duration::from_millis(50);

/// The budget for the frame currently being read, shared between the caller that sets it and the
/// [`DeadlineReader`] that enforces it.
///
/// Cloning shares the same budget: the transport owns one handle and the conversation owns another,
/// so a leg can change the budget between frames without rebuilding the transport.
#[derive(Clone, Debug)]
pub struct FrameBudget(Arc<AtomicU64>);

impl FrameBudget {
    /// A budget of `per_frame` for every frame read through the transport it is installed in.
    pub fn of(per_frame: Duration) -> Self {
        Self(Arc::new(AtomicU64::new(per_frame.as_millis() as u64)))
    }

    /// Give the NEXT frame `budget` instead.
    ///
    /// Takes effect at the next frame boundary, never mid-frame: a frame that has already begun keeps
    /// the bound it started under, so shortening the budget can never retroactively expire a frame
    /// that was arriving legitimately.
    pub fn set(&self, budget: Duration) {
        self.0.store(budget.as_millis() as u64, Ordering::Relaxed);
    }

    fn duration(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::Relaxed))
    }
}

/// A reader that refuses to wait past its [`FrameBudget`] for bytes the peer has not sent.
pub struct DeadlineReader<S> {
    inner: S,
    budget: FrameBudget,
    /// When the frame in flight must be complete. `None` between frames.
    expires_at: Option<Instant>,
}

impl<S: WaitReadable> DeadlineReader<S> {
    /// Bound every frame read from `inner` by `budget`.
    pub fn new(inner: S, budget: FrameBudget) -> Self {
        Self {
            inner,
            budget,
            expires_at: None,
        }
    }
}

impl<S: WaitReadable> Read for DeadlineReader<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let expires_at = *self
            .expires_at
            .get_or_insert_with(|| Instant::now() + self.budget.duration());

        loop {
            let remaining = expires_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(timed_out());
            }
            if !self.inner.wait_readable(remaining.min(WAIT_SLICE))? {
                // Nothing arrived within the slice. Calling read now would block past the deadline on
                // a platform whose read cannot be bounded, which is the whole failure being removed.
                continue;
            }
            match self.inner.read(buf) {
                // A wait that returned without data is not an answer; only the deadline above ends
                // the loop. Both kinds appear because a socket read timeout reports one of them.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => return Err(e),
                Ok(read) => {
                    // The newline IS the frame boundary, so seeing one means the next read starts a
                    // new frame under a fresh budget.
                    if buf[..read].contains(&b'\n') {
                        self.expires_at = None;
                    }
                    return Ok(read);
                }
            }
        }
    }
}

/// The error a caller sees when the peer accepted and then did not answer.
///
/// `TimedOut` specifically, never a bare `Other`: [`super::client`] has to be able to tell a peer that
/// went silent apart from a peer that hung up, because those are different sentences to a person.
pub fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "the peer accepted the connection and then sent nothing",
    )
}

/// A stream that can be asked to wait, boundedly, for readable bytes.
///
/// Implemented per platform because no portable API exists: a Unix socket takes an `SO_RCVTIMEO`, and
/// a Windows synchronous named-pipe handle takes no read timeout at all and has to be peeked.
pub trait WaitReadable: Read {
    /// Wait up to `slice` for bytes to arrive, reporting whether a read may now proceed.
    ///
    /// `Ok(false)` means the slice expired with nothing there, and the caller MUST NOT read: on a
    /// platform whose read cannot be bounded, that read is exactly the unbounded wait this module
    /// exists to remove. `Ok(true)` permits one read attempt and promises nothing more than that.
    fn wait_readable(&mut self, slice: Duration) -> io::Result<bool>;
}

#[cfg(unix)]
impl WaitReadable for std::os::unix::net::UnixStream {
    /// Arm `SO_RCVTIMEO` for this slice and let the kernel do the waiting; the read that follows
    /// reports `WouldBlock` if nothing arrived, which [`DeadlineReader`] treats as "keep waiting until
    /// MY deadline".
    fn wait_readable(&mut self, slice: Duration) -> io::Result<bool> {
        // Zero means "block forever" to the socket layer, which is the exact opposite of what a
        // zero-length slice means here.
        self.set_read_timeout(Some(slice.max(Duration::from_millis(1))))?;
        // The kernel does the waiting, and the armed timeout is what bounds the read that follows —
        // so the read may always be attempted here.
        Ok(true)
    }
}

#[cfg(windows)]
impl WaitReadable for std::fs::File {
    /// Poll the pipe instead of reading it.
    ///
    /// A synchronous named-pipe handle has no read timeout — `SetNamedPipeHandleState`'s collect-data
    /// timeout governs message-mode writes, not a blocking read — so the only way to bound a read
    /// without moving the whole transport to overlapped I/O is to ask first whether a read would
    /// block. `PeekNamedPipe` answers that without consuming a byte.
    fn wait_readable(&mut self, slice: Duration) -> io::Result<bool> {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Pipes::PeekNamedPipe;

        let handle = HANDLE(self.as_raw_handle() as _);
        let deadline = Instant::now() + slice;
        loop {
            let mut available: u32 = 0;
            // SAFETY: `handle` is this file's own live handle, and the only out-parameter is a `u32`
            // owned by this frame.
            let peeked =
                unsafe { PeekNamedPipe(handle, None, 0, None, Some(&mut available), None) };
            match peeked {
                // A broken or closed pipe is the READ's answer to give, not this poll's: reporting it
                // here would dress a hang-up as a wait failure and lose the real error kind.
                Err(_) => return Ok(true),
                Ok(()) if available > 0 => return Ok(true),
                Ok(()) => {}
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A stream that never answers unless the test feeds it, so the deadline logic itself can be
    /// proven without a socket.
    ///
    /// It STALLS rather than closing: a closed stream returns EOF immediately, which every one of the
    /// tests below would pass with no deadline in the code at all.
    #[derive(Default)]
    struct StalledStream {
        pending: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for StalledStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut pending = self.pending.lock().unwrap();
            if pending.is_empty() {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            let n = pending.len().min(buf.len());
            buf[..n].copy_from_slice(&pending[..n]);
            pending.drain(..n);
            Ok(n)
        }
    }

    impl WaitReadable for StalledStream {
        fn wait_readable(&mut self, slice: Duration) -> io::Result<bool> {
            std::thread::sleep(slice.min(Duration::from_millis(5)));
            Ok(!self.pending.lock().unwrap().is_empty())
        }
    }

    /// A silent peer is refused once the budget is spent, and refused as `TimedOut` — which is what
    /// lets the client say "it accepted and did not answer" rather than shrug.
    #[test]
    fn a_silent_peer_is_refused_once_the_budget_is_spent() {
        let mut reader = DeadlineReader::new(
            StalledStream::default(),
            FrameBudget::of(Duration::from_millis(120)),
        );

        let began = Instant::now();
        let error = reader.read(&mut [0u8; 32]).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(began.elapsed() >= Duration::from_millis(120));
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "the budget bounds the wait; it took {:?}",
            began.elapsed()
        );
    }

    /// The budget spans the WHOLE frame, not each read: a peer that dribbles bytes without ever
    /// closing the frame is cut off at the same deadline a fully silent one is.
    ///
    /// This is the property a per-read timeout does NOT have, and the reason the deadline is absolute.
    #[test]
    fn a_dribbling_peer_cannot_extend_the_frame_past_its_budget() {
        let stream = StalledStream::default();
        let pending = stream.pending.clone();
        let feeding = std::thread::spawn(move || {
            for _ in 0..200 {
                pending.lock().unwrap().push(b'x');
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        let mut reader = DeadlineReader::new(stream, FrameBudget::of(Duration::from_millis(150)));
        let began = Instant::now();
        let mut received = 0usize;
        let error = loop {
            match reader.read(&mut [0u8; 1]) {
                Ok(read) => received += read,
                Err(e) => break e,
            }
        };

        // The control on the fixture: a peer that sent NOTHING would time out too, and would prove
        // only what the silent-peer test already proves. This one really was feeding the stream.
        assert!(received > 0, "the dribbling peer never fed the stream");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "a dribbling peer must not extend the frame; it took {:?}",
            began.elapsed()
        );
        feeding.join().unwrap();
    }

    /// A completed frame re-arms the budget, so a long conversation is not charged for the time its
    /// earlier frames took.
    #[test]
    fn each_frame_gets_its_own_budget() {
        let stream = StalledStream::default();
        stream.pending.lock().unwrap().extend_from_slice(b"a\nb\n");
        let mut reader = DeadlineReader::new(stream, FrameBudget::of(Duration::from_millis(200)));

        let mut buf = [0u8; 2];
        assert_eq!(reader.read(&mut buf).unwrap(), 2);
        assert!(reader.expires_at.is_none(), "the newline ended the frame");
        assert_eq!(reader.read(&mut buf).unwrap(), 2);
    }
}
