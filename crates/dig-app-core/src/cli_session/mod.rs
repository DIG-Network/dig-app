//! The `dign` <-> dig-app CLI session: the per-user local lane the DIG command line runs on
//! (epic dig_ecosystem#908, U6).
//!
//! `dign` holds no identity and reaches no node. It parses an invocation into a
//! [`Command`](crate::gateway::Command), hands it to the running dig-app over this lane, and renders
//! what comes back. The app is the front door: it holds the keys, it owns the profile registry, and
//! it — never the CLI — decides whether a command is served locally or proxied onward.
//!
//! # The two boundaries in front of the lane
//!
//! 1. **The endpoint is per-USER, enforced by the OS.** A Windows named pipe carrying an explicitly
//!    built, PROTECTED, owner-only DACL — one access-allowed entry for the calling user's SID, with
//!    `Everyone` and `ANONYMOUS LOGON` excluded — or a Unix socket at mode `0600` inside a `0700`
//!    directory. Another local user cannot open either. A NULL security descriptor is NOT used and
//!    MUST NOT be: it grants `Everyone` `FILE_GENERIC_READ` on a pipe, so the DACL is built rather
//!    than defaulted. See [`transport`], which documents the exact flags and modes.
//! 2. **A session secret proves, in BOTH directions, that the two halves belong to the same app
//!    instance.** Minted fresh from the CSPRNG on every app start and published to an owner-only file
//!    ([`auth`]), it is never transmitted. Instead each half MACs a shared two-nonce transcript under
//!    it: the SERVER proves itself first, on `control.session.challenge`, and only then does the
//!    CLIENT prove itself on `control.session.attach`. Both MACs are compared in constant time. See
//!    [`handshake`].
//!
//! Both must be cleared: the endpoint is unreachable to another user, and the secret is unreadable to
//! them. Neither one being wrong on its own opens the lane.
//!
//! # The boundary holds in BOTH directions, and that is not a detail
//!
//! The endpoint address is derived from the login name, and creating a named pipe or a socket needs no
//! privilege. So the two boundaries above answer two different questions, and BOTH have to be
//! answered:
//!
//! - **Server direction** — may this caller use the lane? The OS-enforced DACL/mode, plus the client
//!   proof, say no to a local principal that cannot read the secret file.
//! - **Client direction** — is the thing answering the lane actually dig-app? Only the server proof
//!   says so. When the app has not bound the endpoint yet, or failed to bind it, or crashed, any local
//!   principal may hold the name; a client that trusted it would print an answer that principal chose,
//!   up to and including a wallet receive address.
//!
//! An earlier version of this lane stated the guarantee in the server direction only, and was
//! therefore built in the server direction only: the client presented the secret to whatever answered.
//! The requirement is mutual, and it is written here in both directions so it cannot be implemented in
//! one again.
//!
//! # What the lane may NOT do (dig_ecosystem#908)
//!
//! The app signs nothing on the user's behalf without the user's own confirmation. A CLI session
//! does not change that: `dign sign` routes through the SAME
//! [`NativeConfirmer`](crate::confirm::NativeConfirmer) ceremony the tray and the dapp channel use,
//! because the server hands every command to the one [`Gateway`](crate::gateway::Gateway) rather
//! than reaching past it. There is no path here that signs without the ceremony, and adding one
//! would be the breach this boundary exists to prevent.

pub mod auth;
pub mod client;
pub mod endpoint;
pub mod engine_proxy;
pub mod handshake;
pub mod host_identity;
pub mod server;
pub mod transport;
pub mod wire;

#[cfg(test)]
mod test_support;

pub use auth::{token_path, SessionToken};
pub use client::{host_endpoint, send, send_via};
pub use endpoint::{cli_endpoint, socket_path};
pub use engine_proxy::NodeEngineProxy;
pub use handshake::Nonce;
pub use host_identity::{HostIdentity, UnavailableConfirmer, UnopenedLinks};
pub use server::{CliSession, CliSessionServer};

/// Why this host is not serving a CLI lane.
///
/// Two failures wear the same shape at the `bind` call and mean completely different things, so they
/// are named apart. Being unable to distinguish them is what let a hijacked endpoint look like an
/// ordinary absent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneFault {
    /// **Another process already holds the endpoint name.** An ATTACK INDICATOR, not a degrade: the
    /// address is derived from the login name, this app is the only legitimate holder of it, and
    /// whatever holds it is now positioned to answer `dign` in the name of dig-app.
    ///
    /// The client proof ([`handshake`]) is what stops that impostor being believed. This fault is how
    /// the app side stops being SILENT about it.
    EndpointHeldByAnother,
    /// The host could not provide the channel at all — no lane, and nothing suspicious about it.
    ChannelUnavailable,
}

impl LaneFault {
    /// Read a bind failure as one of the two faults.
    ///
    /// `PermissionDenied` is the Windows answer (`ERROR_ACCESS_DENIED`, because
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE` refuses a name someone else already created) and `AddrInUse` is
    /// the Unix one. Everything else is an ordinary unavailable channel.
    pub fn from_bind_failure(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrInUse => {
                Self::EndpointHeldByAnother
            }
            _ => Self::ChannelUnavailable,
        }
    }
}

/// The fault recorded by the most recent [`serve_in_background`] bind, if it failed.
///
/// Readable by any diagnostic surface, so "there is no lane" and "something has taken the lane" are
/// distinguishable to an operator after the fact and not only in a log line.
pub fn lane_fault() -> Option<LaneFault> {
    *LANE_FAULT.lock().unwrap_or_else(|e| e.into_inner())
}

static LANE_FAULT: std::sync::Mutex<Option<LaneFault>> = std::sync::Mutex::new(None);

/// Record `fault` and say so where a person can actually see it.
///
/// A hijacked endpoint reported only through `tracing::warn!` reaches nobody in a tray app, which is
/// precisely how this stayed silent. It is recorded for diagnostics, logged at `error`, and written to
/// stderr — and it still does not stop the app, because reading DIG content must never require a
/// working CLI lane (the never-trap-the-user rule).
fn record_lane_fault(fault: LaneFault, error: &std::io::Error, endpoint: &str) {
    *LANE_FAULT.lock().unwrap_or_else(|e| e.into_inner()) = Some(fault);
    match fault {
        LaneFault::EndpointHeldByAnother => {
            tracing::error!(
                error = %error,
                %endpoint,
                "the dign CLI endpoint is already held by another process on this machine — dig-app \
                 is NOT serving the command line, and anything answering `dign` there is not dig-app"
            );
            eprintln!(
                "DIG: the command-line endpoint {endpoint} is already held by another process. \
                 dig-app is not serving `dign`; do not trust output from it until this is resolved."
            );
        }
        LaneFault::ChannelUnavailable => {
            tracing::warn!(error = %error, %endpoint, "the dign CLI lane could not be bound");
        }
    }
}

/// Bind this user's CLI lane and serve it on a background thread, for the life of the process.
///
/// Best-effort by design: a host that cannot bind the lane still gets a working DIG app, and the
/// reason is logged rather than fatal. `dign` then reports `NOT_CONNECTED` with its remedy, which is
/// the same thing a person sees when the app is genuinely not running.
///
/// A bind refused because someone ELSE holds the endpoint is not that ordinary case — see
/// [`LaneFault`], which is recorded and surfaced rather than warned about.
///
/// # Why the seams are built INSIDE the thread
///
/// [`crate::gateway::LocalIdentity`] and [`crate::gateway::LinkOpener`] are deliberately not
/// `Send + Sync`: their test doubles use `RefCell`, and widening the traits to move seams across a
/// thread boundary would force every double to become thread-safe for no behavioural gain. Only the
/// two owned paths cross the boundary; the seams are constructed where they are used.
///
/// # There is no window in which the endpoint is missing
///
/// The bind claims the endpoint before this function's thread reaches its first `accept`, on both
/// platforms, so a `dign` that races start-up either finds the lane or finds nothing at all -- never
/// a half-started lane whose token is published against an unclaimed name. That also makes the
/// bind-failure branch below reachable on Windows, where a squatted pipe name now fails HERE instead
/// of at the first accept.
pub fn serve_in_background(
    endpoint: String,
    brand_dir: std::path::PathBuf,
    node_endpoint: Option<String>,
) {
    let spawned = std::thread::Builder::new()
        .name("dig-app-cli-lane".to_string())
        .spawn(move || {
            let (proxy, identity, opener, confirmer) = (
                NodeEngineProxy::new(node_endpoint),
                HostIdentity::under(&brand_dir),
                UnopenedLinks,
                UnavailableConfirmer,
            );
            let server = match CliSessionServer::bind(
                &endpoint, &brand_dir, &proxy, &identity, &opener, &confirmer,
            ) {
                Ok(server) => server,
                Err(e) => {
                    record_lane_fault(LaneFault::from_bind_failure(&e), &e, &endpoint);
                    return;
                }
            };
            tracing::info!(%endpoint, "the dign CLI lane is serving");
            if let Err(e) = server.serve_blocking() {
                tracing::error!(error = %e, "the dign CLI lane stopped serving");
            }
        });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "could not spawn the dign CLI lane thread");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two bind failures must not collapse into one verdict.
    ///
    /// A squatted endpoint arrives as `ERROR_ACCESS_DENIED` on Windows and `AddrInUse` on Unix, and
    /// for a long time the lane answered both of those, and every other error, with the same warning.
    /// The nearest wrong implementation is exactly that single bucket, so the assertion pairs a
    /// squat-shaped error with an ordinary one and requires them to differ.
    #[test]
    fn a_squatted_endpoint_is_told_apart_from_an_absent_channel() {
        use std::io::{Error, ErrorKind};

        for held in [ErrorKind::PermissionDenied, ErrorKind::AddrInUse] {
            assert_eq!(
                LaneFault::from_bind_failure(&Error::new(held, "access is denied")),
                LaneFault::EndpointHeldByAnother,
                "{held:?} means another process holds the name"
            );
        }
        for ordinary in [
            ErrorKind::NotFound,
            ErrorKind::Other,
            ErrorKind::Unsupported,
        ] {
            assert_eq!(
                LaneFault::from_bind_failure(&Error::new(ordinary, "no channel")),
                LaneFault::ChannelUnavailable,
                "{ordinary:?} is an ordinary missing lane"
            );
        }
    }

    /// The fault is RECORDED, not merely logged: a tray app has no visible log, so an operator asking
    /// after the fact is the only reader this signal ever gets.
    #[test]
    fn a_hijack_is_recorded_where_a_diagnostic_can_read_it() {
        use std::io::{Error, ErrorKind};

        record_lane_fault(
            LaneFault::EndpointHeldByAnother,
            &Error::new(ErrorKind::PermissionDenied, "access is denied"),
            r"\.\pipe\dignetwork-cli-test",
        );
        assert_eq!(lane_fault(), Some(LaneFault::EndpointHeldByAnother));
    }
}
