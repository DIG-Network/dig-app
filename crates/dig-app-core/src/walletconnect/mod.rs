//! WalletConnect v2, wallet side — connecting outside apps to a DIG identity (dig-app#225).
//!
//! WalletConnect is how a website or a phone app asks a wallet for something without either side
//! knowing anything about the other in advance. A person copies a `wc:` link out of the app, pastes
//! it into the wallet, and the two negotiate a session through a public relay that can read neither
//! of them. This module is the wallet half of that, at parity with Sage's implementation and in
//! DIG's tray-native idiom.
//!
//! # Where the parts live
//!
//! | module | what it owns |
//! |---|---|
//! | [`uri`] | reading the `wc:` string a person pastes — a trust boundary, since it arrives from a clipboard |
//! | [`crypto`] | the relay envelope and the X25519/HKDF session-key exchange |
//! | [`session`] | what a settled session IS, and its sealed-at-rest per-profile store |
//! | [`request`] | what a connected dapp may ask for, and the consent + signing that answers it |
//! | [`journey`] | the two tray verbs: connect an app, manage the apps connected |
//! | [`relay`] | the websocket transport to the WalletConnect relay |
//!
//! # The custody boundary, stated once
//!
//! **The user's key never leaves this process, and nothing WalletConnect-shaped is ever sent to
//! dig-node** (dig_ecosystem#908). dig-app holds the identity and signs locally; the node reads
//! chain and pushes bundles that were already signed. WalletConnect is a signing TRANSPORT, which
//! makes it the surface most likely to violate that boundary by accident, so the arrangement here is
//! deliberate and narrow:
//!
//! - the relay is reached by [`relay`], which moves opaque sealed envelopes and holds no key;
//! - the only key material this module handles is the per-session symmetric key and an ephemeral
//!   X25519 secret, both of which exist solely to talk to the dapp and neither of which can sign
//!   anything on chain;
//! - the identity key is reached ONLY through the [`request::WcSigner`] seam, whose whole surface is
//!   "here are some bytes, give me a detached signature or tell me you are locked". A signature is
//!   produced in-process, by the same signer the loopback channel uses, and the bytes it signs are
//!   built by this crate rather than supplied by the dapp;
//! - there is no code path from here to the node's control interface, and none should ever be added.
//!   dig-node#327 records a surviving node-side signing surface scheduled for removal under
//!   dig_ecosystem#1701; WalletConnect deliberately does not use it, because anything wired into it
//!   dies with it.
//!
//! # Consent
//!
//! Connecting is one human approval. Signing is another, every time, with no remembered permission
//! that could turn the first into the second. Both are drawn by the same
//! [`NativeConfirmer`](crate::confirm::NativeConfirmer) every other privileged action in this app
//! uses, so there is one consent surface rather than a WalletConnect-shaped second one.

pub mod crypto;
pub mod journey;
pub mod relay;
pub mod request;
pub mod session;
pub mod uri;

pub use journey::{
    connect_walletconnect, manage_walletconnect, ConnectOutcome, ManageOutcome, ProposalError,
    SessionProposal, WalletConnectSurface, WC_NOT_CONFIGURED_ADVICE,
};
pub use relay::{RelayConfig, RelayError, DEFAULT_RELAY_URL};
pub use request::{
    handle_request, ProfileFacts, WcReauthGate, WcRequestError, WcSigner, SUPPORTED_EVENTS,
    SUPPORTED_METHODS,
};
pub use session::{
    DappMetadata, DisconnectOutcome, WcSession, WcSessionStore, SESSION_TTL_SECS,
};
pub use uri::{UriError, WcUri};
