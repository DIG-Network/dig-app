//! # dig-node-control-interface — the canonical client ⇄ dig-node CONTROL interface contract
//!
//! This crate is the single source of truth for the management/query surface a client — the CLI
//! `dign`, the browser extension, dig-app, or hub — uses to **control and query a running
//! dig-node**: node configuration, cache configuration, hosted/pinned stores, §21 whole-store sync,
//! the peer network, subscription lifecycle, the auto-update beacon, live log level, and the
//! control-token pairing handshake. Both the node (the server side, dispatching these calls) and
//! every client (the callers) depend on THIS crate rather than each maintaining a byte-identical
//! copy of the method catalog, so the two can never silently drift.
//!
//! ## The catalog
//!
//! - [`ControlMethod`] — every control method's stable wire name, auth requirement, routing, and
//!   category; the enumeration a machine reads to discover the whole surface.
//! - [`params`] — a typed request-params struct per method, each bound (via [`ControlCall`]) to its
//!   method and its typed result.
//! - [`results`] — the typed result payloads, field-for-field with what dig-node emits.
//!   Includes [`PeerSoftware`], the one interpreted member of the otherwise-proxied
//!   `control.peerStatus` snapshot: a peer's advertised software build, defined here so every
//!   client reads a gossip handshake's `software_version` string the same way.
//! - [`error`] — the stable control-error taxonomy ([`ControlErrorCode`]) + the [`ControlError`]
//!   envelope a client branches its UX off.
//! - [`envelope`] — the minimal JSON-RPC 2.0 request/response the catalog rides in.
//! - [`traits`] — the two contract traits: [`ControlClient`] (client-facing: build request / parse
//!   response) and [`ControlHandler`] (node-facing: implement to serve, with a routing dispatcher).
//!
//! ## Boundary (the 6th directed-boundary contract crate)
//!
//! - **dig-rpc-protocol** — node ⇄ node peer wire (PublicRead + Peer tiers).
//! - **dig-ipc-protocol** — app ⇄ node local session/signing envelope (the transport a client
//!   authenticates over).
//! - **dig-node-control-interface (this crate)** — the CONTROL METHOD CATALOG a client sends
//!   *inside* that authenticated channel (or over loopback-mTLS + a signed control token, per
//!   CLAUDE.md §5.3): the method names, parameter/result types, and error taxonomy.
//!
//! This crate is deliberately **transport-agnostic** — it describes WHAT a client can ask a node to
//! do and what the node replies, not HOW the bytes travel. Consumers pick the transport and carry
//! these types over it.
//!
//! ## Example — build a typed request and parse the response
//!
//! ```
//! use dig_node_control_interface::{
//!     params::SetCapParams,
//!     traits::{build_request, parse_response},
//!     envelope::JsonRpcResponse,
//! };
//! use serde_json::json;
//!
//! let call = SetCapParams { cap_bytes: 128 * 1024 * 1024 };
//! let req = build_request(1.into(), &call);
//! assert_eq!(req.method, "control.cache.setCap");
//!
//! // The node replies with the applied cap; parse it back into the typed result.
//! let resp = JsonRpcResponse::success(1.into(), json!({ "cap_bytes": 128 * 1024 * 1024 }));
//! let out = parse_response::<SetCapParams>(resp).unwrap();
//! assert_eq!(out.cap_bytes, 128 * 1024 * 1024);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod envelope;
pub mod error;
pub mod method;
pub mod params;
pub mod results;
pub mod traits;

#[cfg(test)]
mod kats;

pub use error::{ControlError, ControlErrorCode, ControlErrorData};
pub use method::{Category, ControlMethod, Routing};
pub use results::{PeerSoftware, SoftwareVersionDetail};
pub use traits::{ControlCall, ControlClient, ControlHandler, DefaultControlClient};

/// The crate's semantic version, exposed so consumers can assert compatibility at runtime without
/// re-parsing `Cargo.toml`.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
