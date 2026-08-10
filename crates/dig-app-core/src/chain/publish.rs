//! [`ControlSpendPublisher`] — the WRITE half, and the only thing on the money path that touches
//! the network.
//!
//! # The custody boundary (§908), stated as what this file may contain
//!
//! It pushes an ALREADY-SIGNED bundle and nothing else. There is no key, no seed, no phrase and no
//! unsigned-spend-for-the-node-to-sign anywhere here, and the control parameter it sends
//! ([`WalletBroadcastParams`]) has exactly one field: hex of a serialized [`SpendBundle`]. Signing
//! happens in dig-account, in this process, under the user's unlocked account. If a future change
//! would put anything else across this boundary, it is the boundary that is right.
//!
//! # Why the push needs a token when every read does not
//!
//! The five chain reads are OPEN — they answer public chain facts about a value the caller named.
//! This one puts bytes on the network, so the control token is what stands between any local
//! process and a broadcast. That asymmetry is why [`PublishFailure`] separates *this app holds no
//! token* from *no node answered*: on a read those are the same fault (an old node), and on the
//! push they are opposite ones with opposite remedies.

use chia_protocol::SpendBundle;
use chia_traits::Streamable;
use dig_account::mint::{ChainUnavailable, PushOutcome, SpendPublisher};
use dig_node_control_interface::error::ControlErrorCode;
use dig_node_control_interface::method::ControlMethod;
use dig_node_control_interface::params::WalletBroadcastParams;
use std::time::Duration;

use crate::control::{self, ControlCallError, ControlFailure};

/// `control.wallet.broadcast`, named from the contract's own table.
const METHOD: &str = ControlMethod::WalletBroadcast.name();

/// How long one push may take before it is abandoned.
///
/// The node forwards the bundle to a mempool, so this is a network round trip beyond loopback and
/// is budgeted like the chain reads rather than like a liveness probe.
pub const PUSH_TIMEOUT: Duration = Duration::from_secs(20);

/// Why a push did not reach a mempool's judgement.
///
/// # Why this exists beside [`ChainUnavailable`]
///
/// [`SpendPublisher::push`] has two positions: a [`PushOutcome`] when the network ANSWERED, and
/// `ChainUnavailable` when it could not be asked. Every variant here is the second position — the
/// bundle was never judged — so all of them map to `ChainUnavailable`, and none of them may become
/// a [`PushOutcome::Rejected`]. Collapsing them would tell the caller the mempool said no, and the
/// remedies invert: a rejected bundle must be REBUILT, while an unasked one must be RETRIED as-is.
///
/// What the extra type buys is the *diagnosis*, which `ChainUnavailable` flattens to prose. A local
/// refusal for a missing token and an absent node are wholly different situations — one is fixed by
/// running dig-app with access to the node's token, the other by starting a node — and a caller (or
/// a test) that can only read a sentence cannot tell them apart. So the concrete publisher exposes
/// [`ControlSpendPublisher::push_detailed`], and the trait method is a thin, message-preserving map
/// over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishFailure {
    /// This app holds no control token, so the push was **refused before it was sent**.
    ///
    /// A local decision with a local cause: the node was never asked. Distinct from
    /// [`Unreachable`](Self::Unreachable) because the node may be perfectly healthy — dig-node runs
    /// as a service and its master token is a file this user may simply not be able to read.
    NoToken,
    /// The node was asked and refused for authorization: the token presented is not one it knows.
    ///
    /// Distinct from the same code on a READ, where it can only mean an old node (a read needs no
    /// token, so a refusal cannot be about one). Here it genuinely is about the credential.
    Unauthorized {
        /// The node's own message, for a diagnosis. Never branched on.
        detail: String,
    },
    /// Nothing answered at the endpoint, or the answer did not finish or could not be read.
    Unreachable {
        /// What went wrong.
        detail: String,
    },
    /// This dig-node does not serve `control.wallet.broadcast` at all — an older build.
    Unsupported {
        /// The node's own message.
        detail: String,
    },
    /// The node understood the push and answered that IT could not complete it.
    NodeCouldNotAnswer {
        /// The node's own message.
        detail: String,
    },
    /// The bundle could not be serialized for the wire. A local, deterministic fault.
    Unserializable {
        /// What failed.
        detail: String,
    },
}

impl std::fmt::Display for PublishFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoToken => write!(
                f,
                "{METHOD} was not sent: this app holds no dig-node control token, and the push is \
                 the one wallet method that requires one"
            ),
            Self::Unauthorized { detail } => write!(
                f,
                "{METHOD} was refused: the node does not recognise this control token ({detail})"
            ),
            Self::Unreachable { detail } => write!(f, "{METHOD} could not reach a node: {detail}"),
            Self::Unsupported { detail } => write!(
                f,
                "{METHOD} is not served by this dig-node — upgrade it ({detail})"
            ),
            Self::NodeCouldNotAnswer { detail } => {
                write!(f, "the node could not complete {METHOD}: {detail}")
            }
            Self::Unserializable { detail } => {
                write!(f, "{METHOD} was not sent: the bundle could not be encoded ({detail})")
            }
        }
    }
}

impl std::error::Error for PublishFailure {}

/// Pushes already-signed bundles through the local dig-node's control plane.
pub struct ControlSpendPublisher {
    /// The `http://…` control endpoint, already resolved off the §5.3 ladder.
    endpoint: String,
    /// Reads the node's control token at the moment of a push.
    ///
    /// A function rather than a stored `Option<String>`, matching the `read_token: fn() -> Option<String>`
    /// shape five existing call sites use: the token is a file the node may rewrite, and a value
    /// captured at construction would go stale in a long-lived tray process.
    read_token: fn() -> Option<String>,
    /// How long one push may take.
    timeout: Duration,
}

impl ControlSpendPublisher {
    /// A publisher pushing through the node at `endpoint`, reading the control token from disk on
    /// each push via [`control::load_control_token`].
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self::with_token_reader(endpoint, control::load_control_token, PUSH_TIMEOUT)
    }

    /// [`new`](Self::new) with an explicit token reader and budget, so a test can express the
    /// token-less machine without touching process-global state.
    pub fn with_token_reader(
        endpoint: impl Into<String>,
        read_token: fn() -> Option<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            read_token,
            timeout,
        }
    }

    /// Push `bundle`, keeping the typed reason a push did not reach a judgement.
    ///
    /// `Ok` means the mempool ANSWERED — including [`PushOutcome::Rejected`], which is a judgement
    /// and therefore a success of this call. `Err` means it never did; see [`PublishFailure`].
    pub fn push_detailed(&self, bundle: &SpendBundle) -> Result<PushOutcome, PublishFailure> {
        // Refused locally, before a byte goes out. A token-less push cannot succeed, and sending it
        // anyway would turn a knowable local fault into whatever the node's refusal happens to look
        // like -- which is the same shape an absent node produces.
        let Some(token) = (self.read_token)() else {
            return Err(PublishFailure::NoToken);
        };

        let signed_bundle_hex = bundle
            .to_bytes()
            .map(hex::encode)
            .map_err(|e| PublishFailure::Unserializable {
                detail: e.to_string(),
            })?;

        let answer = control::call_control_result(
            &self.endpoint,
            &WalletBroadcastParams { signed_bundle_hex },
            Some(&token),
            self.timeout,
        )
        .map_err(publish_failure_from)?;

        Ok(match (answer.accepted, answer.rejection) {
            (true, _) => PushOutcome::Accepted,
            (false, Some(reason)) if already_in_mempool(&reason) => PushOutcome::AlreadyInMempool,
            (false, Some(reason)) => PushOutcome::Rejected { reason },
            // Not accepted and no reason given. The node has said the bundle is not in a mempool
            // while declining to say what judged it, so nothing here is entitled to call it a
            // mempool rejection -- that would send the caller to rebuild a bundle that may be fine.
            (false, None) => {
                return Err(PublishFailure::NodeCouldNotAnswer {
                    detail: "the node reported the bundle was not accepted and gave no reason"
                        .into(),
                })
            }
        })
    }
}

/// Whether a mempool's refusal is the benign "I already have this one".
///
/// A duplicate is the same success arrived at twice — the bundle IS in a mempool — so reporting it
/// as a rejection would have a caller rebuild a spend that is already in flight, and possibly spend
/// twice. Matched case-insensitively on the mempool's own status token.
fn already_in_mempool(reason: &str) -> bool {
    let reason = reason.to_ascii_uppercase();
    reason.contains("ALREADY_INCLUDING_TRANSACTION") || reason.contains("DOUBLE_SPEND_IN_MEMPOOL")
}

/// Map a failed push onto the arm whose remedy is the right one.
fn publish_failure_from(failure: ControlFailure) -> PublishFailure {
    match failure {
        ControlFailure::Transport(ControlCallError::HttpRefused { code, detail })
            if matches!(code, 401 | 403) =>
        {
            PublishFailure::Unauthorized {
                detail: format!("HTTP {code} {detail}"),
            }
        }
        ControlFailure::Transport(e) => PublishFailure::Unreachable {
            detail: e.to_string(),
        },
        ControlFailure::Rejected(e) => match e.code_enum() {
            Some(ControlErrorCode::Unauthorized) => PublishFailure::Unauthorized {
                detail: e.message,
            },
            Some(ControlErrorCode::MethodNotFound) => PublishFailure::Unsupported {
                detail: e.message,
            },
            _ => PublishFailure::NodeCouldNotAnswer { detail: e.message },
        },
    }
}

impl SpendPublisher for ControlSpendPublisher {
    /// The canonical seam, preserving [`push_detailed`](Self::push_detailed)'s sentence.
    ///
    /// Every [`PublishFailure`] becomes a [`ChainUnavailable`] because every one of them means the
    /// mempool never judged the bundle — which is precisely what `ChainUnavailable` denotes. In
    /// particular a token-less push does NOT become a [`PushOutcome::Rejected`]: no mempool said no,
    /// and claiming one did would have dig-account discard a perfectly good bundle.
    fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome, ChainUnavailable> {
        self.push_detailed(bundle)
            .map_err(|failure| ChainUnavailable::new(failure.to_string()))
    }
}
