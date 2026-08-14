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
/// a test) that can only read a sentence cannot tell them apart. So this type is what
/// [`DetailedSpendPublisher::push_detailed`] returns, and `SpendPublisher::push` is a thin,
/// message-preserving map over it.
///
/// The send path needs more than a diagnosis: it needs to know whether these bytes could be in a
/// mempool right now, because that decides both what a person is told and whether they may send
/// again. [`may_have_reached_a_mempool`](Self::may_have_reached_a_mempool) is that judgement.
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

impl PublishFailure {
    /// Whether these bytes could conceivably be sitting in a mempool despite this failure.
    ///
    /// This is the question the SEND path turns into what a person is told, and the two answers lead
    /// to opposite advice. `false` means the bundle provably never left — the caller may say *nothing
    /// was sent* and offer the form again. `true` means nobody knows, and the only safe move is to
    /// watch the payment coin, because building a second transfer can pay the recipient twice.
    ///
    /// # Why each variant falls where it does
    ///
    /// Four of them are decided BEFORE any bundle could be in flight: [`NoToken`](Self::NoToken) is
    /// refused locally with no byte on the wire, [`Unserializable`](Self::Unserializable) never
    /// produced bytes to send, and [`Unsupported`](Self::Unsupported) and
    /// [`Unauthorized`](Self::Unauthorized) are the node's own ANSWER declining to serve or to accept
    /// the credential — an answer that arrives instead of a broadcast, not after one.
    ///
    /// The other two cannot be decided from here. [`Unreachable`](Self::Unreachable) covers a
    /// connection that may have dropped after the request was written, and
    /// [`NodeCouldNotAnswer`](Self::NodeCouldNotAnswer) is a node that took the bundle and then said
    /// something unusable — including the timeout case, where it may already have forwarded it.
    ///
    /// # The direction the uncertainty is resolved in
    ///
    /// Deliberately towards `true`. A variant misplaced on the unknown side costs a person a wait; one
    /// misplaced on the definite side tells them nothing was sent while a bundle is live, which is the
    /// double-payment this whole flow exists to prevent. A new variant therefore belongs on the
    /// unknown side until someone can show it cannot be in flight — and the match below has no
    /// wildcard, so adding one forces that judgement rather than inheriting a neighbour's.
    pub fn may_have_reached_a_mempool(&self) -> bool {
        match self {
            Self::NoToken
            | Self::Unserializable { .. }
            | Self::Unsupported { .. }
            | Self::Unauthorized { .. } => false,
            Self::Unreachable { .. } | Self::NodeCouldNotAnswer { .. } => true,
        }
    }
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
                write!(
                    f,
                    "{METHOD} was not sent: the bundle could not be encoded ({detail})"
                )
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
}

/// A publisher that keeps the REASON a push did not reach a mempool.
///
/// # Why this exists beside [`SpendPublisher`]
///
/// `SpendPublisher` is dig-account's seam and reports one failure: [`ChainUnavailable`], a sentence.
/// That is the right shape for the MINT, which retries the whole ceremony either way. It is the wrong
/// shape for a SEND, where the reason decides what a person is told and what they may do next: a push
/// refused for a missing token sent nothing and the form should come straight back, while a push
/// nobody answered may be settling right now and a second send could pay the recipient twice
/// (`may_have_reached_a_mempool` is where that line is drawn).
///
/// So the send path is generic over THIS trait, and the flattening `SpendPublisher` impl stays for
/// the callers that genuinely cannot act on the difference. Both are the same one operation — push an
/// already-signed bundle — and this trait adds no capability beyond keeping the diagnosis.
pub trait DetailedSpendPublisher {
    /// Push `bundle`, keeping the typed reason a push did not reach a judgement.
    ///
    /// `Ok` means the mempool ANSWERED — including [`PushOutcome::Rejected`], which is a judgement
    /// and therefore a success of this call. `Err` means it never did; see [`PublishFailure`].
    fn push_detailed(&self, bundle: &SpendBundle) -> Result<PushOutcome, PublishFailure>;
}

impl DetailedSpendPublisher for ControlSpendPublisher {
    fn push_detailed(&self, bundle: &SpendBundle) -> Result<PushOutcome, PublishFailure> {
        // Refused locally, before a byte goes out. A token-less push cannot succeed, and sending it
        // anyway would turn a knowable local fault into whatever the node's refusal happens to look
        // like -- which is the same shape an absent node produces.
        let Some(token) = (self.read_token)() else {
            return Err(PublishFailure::NoToken);
        };

        let signed_bundle_hex =
            bundle
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
            // Accepted, and the node kept quiet about a refusal -- the only shape the contract
            // allows for an acceptance (`rejection` is "null on acceptance").
            (true, None) => PushOutcome::Accepted,
            (true, Some(reason)) if reason.trim().is_empty() => PushOutcome::Accepted,
            // Accepted AND refused at once. The wire shape cannot forbid this, and the mirror-image
            // contradiction below is already refused on the same reasoning -- but this one resolves
            // optimistically ("your money moved") if believed, which is the worse of the two
            // directions to guess in. So it is not believed.
            (true, Some(reason)) => {
                return Err(PublishFailure::NodeCouldNotAnswer {
                    detail: format!(
                        "the node reported the bundle both accepted and refused ({reason}), so \
                         what the mempool did with it is unknown"
                    ),
                })
            }
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
/// twice. This is the ONLY refusal that means that: chia's error enum names it
/// `ALREADY_INCLUDING_TRANSACTION` (109), and its neighbours in the same family —
/// `MEMPOOL_CONFLICT` (19, *another* item spends one of these coins), `DOUBLE_SPEND` (5) and
/// `DOUBLE_SPEND_IN_FORK` (122) — are genuine refusals of THIS bundle and must stay
/// [`PushOutcome::Rejected`], because the remedy for them is a rebuild.
///
/// # This is a best-effort match over prose the contract does not pin
///
/// [`WalletBroadcastResult::rejection`](dig_node_control_interface::results::WalletBroadcastResult::rejection)
/// is documented as free-form prose explaining why the mempool refused — not a status token — so no
/// exhaustive classification of it is possible from here. The match is therefore deliberately the
/// NARROWEST one that recognises the duplicate: the whole trimmed reason, compared without case,
/// and nothing else.
///
/// A substring match would be the defect. `rejection` reaches this function from the node, and a
/// COMPROMISED node is attacker-controlled by definition: with `contains`, such a node could embed
/// the token inside other prose and have its REFUSAL reported as [`PushOutcome::AlreadyInMempool`],
/// which dig-account folds into `Ok(())` — telling the user a mint is in flight that was in fact
/// refused. An exact match makes that string unreachable from any refusal that is not literally the
/// duplicate token.
///
/// # Which direction the residual uncertainty fails in, chosen deliberately
///
/// An honest duplicate whose wording differs from the bare token is classified as `Rejected`, and
/// the caller rebuilds. That direction was chosen over widening the match because the mempool
/// itself refuses the rebuilt bundle for the same reason the original was a duplicate, so the error
/// is self-correcting; widening it fails the other way, silently converting refusals into reported
/// successes, which has no such backstop.
fn already_in_mempool(reason: &str) -> bool {
    reason
        .trim()
        .eq_ignore_ascii_case("ALREADY_INCLUDING_TRANSACTION")
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
            Some(ControlErrorCode::Unauthorized) => {
                PublishFailure::Unauthorized { detail: e.message }
            }
            Some(ControlErrorCode::MethodNotFound) => {
                PublishFailure::Unsupported { detail: e.message }
            }
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
