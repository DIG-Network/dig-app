//! The CLI / RPC gateway — the user app is the front door (U7).
//!
//! *This module is a U1 skeleton; U7 implements it to `SPEC.md`.*
//!
//! `dign` (the DIG user CLI, owned by dig-app) and RPC clients connect to the user app's local
//! endpoint ([`crate::ipc`], §5.3 tier-0). The user app authenticates the caller and either handles
//! the request with its keys (sign / profile operations) or proxies engine work over the
//! identity-authenticated session to the dig-node engine. The `dig-node` binary retains ONLY
//! machine service-lifecycle subcommands (install/start/stop/status/uninstall/run-service); every
//! user/identity subcommand moves here.

/// Where a gateway request is served. U7 fills in the request/response plumbing; U1 names the
/// routing decision so the SPEC's "handle-locally vs proxy-to-engine" split is explicit in code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Served locally by the user app using the held user identity (sign / profile / wallet).
    UserApp,
    /// Proxied over the authenticated session to the identity-agnostic engine (serve / peers /
    /// content reads).
    Engine,
}
