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
//! 1. **The endpoint is per-USER, enforced by the OS.** A Windows named pipe carrying this user's
//!    default DACL, or a Unix socket at mode `0600` inside a `0700` directory. Another local user
//!    cannot open either. See [`transport`], which documents the exact flags and modes.
//! 2. **An attach token proves the client belongs to THIS app instance.** Minted fresh from the
//!    CSPRNG on every app start, published to an owner-only file, presented on
//!    `control.session.attach`, and compared in constant time. See [`auth`].
//!
//! Both must be cleared: the endpoint is unreachable to another user, and the token is unreadable to
//! them. Neither one being wrong on its own opens the lane.
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
pub mod host_identity;
pub mod server;
pub mod transport;
pub mod wire;

#[cfg(test)]
mod test_support;

pub use auth::{token_path, SessionToken};
pub use client::{host_endpoint, send, send_via};
pub use endpoint::{cli_endpoint, socket_path};
pub use host_identity::{HostIdentity, UnavailableConfirmer, UnopenedLinks};
pub use server::{CliSession, CliSessionServer};

/// Bind this user's CLI lane and serve it on a background thread, for the life of the process.
///
/// Best-effort by design: a host that cannot bind the lane still gets a working DIG app, and the
/// reason is logged rather than fatal. `dign` then reports `NOT_CONNECTED` with its remedy, which is
/// the same thing a person sees when the app is genuinely not running.
///
/// # Why the seams are built INSIDE the thread
///
/// [`crate::gateway::LocalIdentity`] and [`crate::gateway::LinkOpener`] are deliberately not
/// `Send + Sync`: their test doubles use `RefCell`, and widening the traits to move seams across a
/// thread boundary would force every double to become thread-safe for no behavioural gain. Only the
/// two owned paths cross the boundary; the seams are constructed where they are used.
pub fn serve_in_background(endpoint: String, brand_dir: std::path::PathBuf) {
    let spawned = std::thread::Builder::new()
        .name("dig-app-cli-lane".to_string())
        .spawn(move || {
            let (identity, opener, confirmer) = (
                HostIdentity::under(&brand_dir),
                UnopenedLinks,
                UnavailableConfirmer,
            );
            let server = match CliSessionServer::bind(
                &endpoint, &brand_dir, &identity, &opener, &confirmer,
            ) {
                Ok(server) => server,
                Err(e) => {
                    tracing::warn!(error = %e, %endpoint, "the dign CLI lane could not be bound");
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
