//! [`ChainReadError`] — the ONE error type every control-plane chain read fails with.
//!
//! # Why a concrete type at all
//!
//! [`ChainSource`](dig_chainsource_interface::ChainSource) carries an associated `Error`, so the
//! implementation has to pin one. Pinning a concrete enum rather than a boxed `dyn Display` is what
//! lets a caller — and, more importantly, a TEST — assert *which* failure happened. The three
//! properties this module exists to guarantee are all statements about which arm a given wire
//! condition lands in, and none of them is expressible against an opaque string.
//!
//! # The rule the whole module is built around
//!
//! `Ok(None)` and an empty `Vec` are ANSWERS. They are reachable only from a node that consulted a
//! chain and reported an absence. **No failure of any kind may become one.**
//!
//! For [`coin_spend`](dig_chainsource_interface::ChainSource::coin_spend) this is money-critical
//! rather than merely tidy: `Ok(None)` there means *the coin is unspent or unknown*, which a caller
//! reads as **safe to spend** and as *this is the singleton's tip*. A dropped connection rendered as
//! an absence is therefore a double-spend enabler and a walk that stops early on a superseded coin.
//! There is a live instance of exactly this mistake in the ecosystem to not copy: dig-node's own
//! `ChiaQueryLineage::parent_spend` swallows every error into `Ok(None)` (dig_ecosystem#2594).

use std::fmt;

use crate::control::{ControlCallError, ControlFailure};

/// Why a control-plane chain read did not produce an answer.
///
/// Every arm means *the answer is unknown*. None of them may ever be flattened into an absence —
/// see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainReadError {
    /// The node could not be reached, did not finish answering, or answered that IT could not
    /// answer (an unreachable chain source, a failed read, a rate limit).
    ///
    /// The remedy is to **retry**: nothing about the chain has been established.
    Transport {
        /// The `control.*` method that was asked, so a log names the read rather than "a read".
        method: &'static str,
        /// What went wrong, for a human diagnosis. Never branched on — the node's prose is not
        /// contract-stable.
        detail: String,
    },
    /// The node answered, and the answer could not be believed: an unparsable field, a hex string
    /// of the wrong length, or a reply that contradicts the contract it claims to implement.
    ///
    /// The remedy is a **bug report**, against whichever side is wrong. Deliberately NOT
    /// [`Transport`](Self::Transport): retrying a deterministic parse failure is a spin, and
    /// treating a self-contradictory answer as a transient blip is how a malformed reply gets
    /// silently retried into acceptance.
    Malformed {
        /// The `control.*` method whose reply could not be read.
        method: &'static str,
        /// What about the reply could not be believed.
        detail: String,
    },
    /// This node cannot serve the read at all — it does not implement the method, or this client
    /// deliberately does not implement the call.
    ///
    /// The remedy is to **upgrade** (the node, or dig-app), and it is a distinct remedy from either
    /// of the other two. See [`from_open_read_failure`](Self::from_open_read_failure) for why an
    /// authorization refusal on an OPEN read lands here rather than being reported as a missing
    /// token.
    Unsupported {
        /// The `control.*` method that is not available, or the trait method that is not built.
        method: &'static str,
        /// What is missing, and what would supply it.
        detail: String,
    },
    /// The node answered TRUTHFULLY and the answer exceeds a bound this client refuses to cross —
    /// a singleton lineage deeper than the canonical hop cap, or a puzzle reveal that expands past
    /// the hostile-input size bound.
    ///
    /// The remedy is to **report it**, and specifically NOT to retry: the bound is deterministic, so
    /// a second attempt refuses identically.
    ///
    /// # Why this is not [`Malformed`](Self::Malformed)
    ///
    /// `Malformed` says *the node's answer could not be believed*. Here it could: the data may be
    /// perfectly well-formed and may hash correctly, and it is refused for its SIZE alone.
    /// `dig-chainsource-interface` keeps `RevealTooLarge` and `LineageTooDeep` as their own variants
    /// for exactly this reason — collapsing them accuses an honest source of serving bad data for
    /// the crime of serving a big one, and a consumer that cannot tell *too big* from *corrupt*
    /// cannot tell a hostile peer from a heavy one.
    Unusable {
        /// The trait method whose answer was refused.
        method: &'static str,
        /// Which bound was crossed, and by what.
        detail: String,
    },
}

impl ChainReadError {
    /// Map a failed OPEN (token-less) control read onto the arm whose remedy is the right one.
    ///
    /// # Why `UNAUTHORIZED` means *upgrade* here, and not *get a token*
    ///
    /// The contract is emphatic that a missing method and a refused one demand opposite remedies,
    /// and on an open read the two are genuinely indistinguishable from the wire: dig-node checks
    /// authorization BEFORE it resolves the method name, so a token-less probe of a name the node
    /// has never heard of answers `-32030 UNAUTHORIZED` rather than `-32601 METHOD_NOT_FOUND`. An
    /// HTTP `401` before any JSON-RPC body exists says the same thing.
    ///
    /// Every read this client makes is one the 0.10 contract declares OPEN, so a conforming node
    /// serves it token-less. A refusal therefore cannot mean *this caller needed a token* — the
    /// method needs none — and can only mean the node predates the method being open, or predates
    /// the method entirely. Both are fixed by upgrading the node. Reporting "get a control token"
    /// would send somebody to provision a credential that would change nothing.
    ///
    /// The gated PUSH is the opposite case and is handled by
    /// [`crate::chain::PublishFailure`], which keeps the two apart precisely because they are not
    /// the same fault.
    pub fn from_open_read_failure(method: &'static str, failure: ControlFailure) -> Self {
        use dig_node_control_interface::error::ControlErrorCode;

        match failure {
            ControlFailure::Transport(ControlCallError::HttpRefused { code, detail })
                if matches!(code, 401 | 403) =>
            {
                Self::Unsupported {
                    method,
                    detail: format!(
                        "the node refused {method} with HTTP {code} even though the 0.10 contract \
                         declares it an OPEN read, so this node predates it — upgrade dig-node \
                         ({detail})"
                    ),
                }
            }
            ControlFailure::Transport(e) => Self::Transport {
                method,
                detail: e.to_string(),
            },
            ControlFailure::Rejected(e) => match e.code_enum() {
                Some(ControlErrorCode::MethodNotFound | ControlErrorCode::Unauthorized) => {
                    Self::Unsupported {
                        method,
                        detail: format!(
                            "this dig-node does not serve {method} (it answered {}), which the \
                             0.10 contract declares an OPEN read — upgrade dig-node",
                            e.code
                        ),
                    }
                }
                // Every other catalogued refusal — no chain source, a failed read, a rate limit —
                // is the node saying it COULD NOT ANSWER. That is unknown-ness, not an absence, and
                // retrying is the remedy.
                _ => Self::Transport {
                    method,
                    detail: format!("the node could not answer {method}: {}", e.message),
                },
            },
        }
    }

    /// A reply that could not be believed.
    pub fn malformed(method: &'static str, detail: impl Into<String>) -> Self {
        Self::Malformed {
            method,
            detail: detail.into(),
        }
    }

    /// A read this client deliberately does not implement.
    pub fn unsupported(method: &'static str, detail: impl Into<String>) -> Self {
        Self::Unsupported {
            method,
            detail: detail.into(),
        }
    }

    /// A read abandoned by this client's own bound rather than by the node.
    pub fn transport(method: &'static str, detail: impl Into<String>) -> Self {
        Self::Transport {
            method,
            detail: detail.into(),
        }
    }

    /// A truthful answer this client refuses for its size or depth.
    pub fn unusable(method: &'static str, detail: impl Into<String>) -> Self {
        Self::Unusable {
            method,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ChainReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { method, detail } => write!(f, "{method} could not be read: {detail}"),
            Self::Malformed { method, detail } => {
                write!(f, "{method} answered something unreadable: {detail}")
            }
            Self::Unsupported { method, detail } => write!(f, "{method} is unavailable: {detail}"),
            Self::Unusable { method, detail } => {
                write!(f, "{method} answered beyond what DIG will process: {detail}")
            }
        }
    }
}

impl std::error::Error for ChainReadError {}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_node_control_interface::error::{ControlError, ControlErrorCode};

    const METHOD: &str = "control.wallet.coinSpend";

    /// **An `UNAUTHORIZED` on an OPEN read can never be reported as a missing token.**
    ///
    /// This is the property requirement 3 names. dig-node authorizes before it resolves a method
    /// name, so a token-less probe of a method it has never heard of comes back `-32030`, not
    /// `-32601` — the two are indistinguishable from the wire. Since every read here is contractually
    /// open, the ONLY honest reading of either is "this node is too old", and the remedy is an
    /// upgrade. A client that said "get a token" would send somebody to provision a credential the
    /// method does not take.
    ///
    /// The fixture varies ONE thing — which refusal code arrives — across the two codes that must
    /// agree, and asserts on the arm AND on the remedy word, because an arm alone would still let
    /// the sentence say the wrong thing.
    #[test]
    fn unauthorized_and_method_not_found_both_say_upgrade_on_an_open_read() {
        for code in [
            ControlErrorCode::Unauthorized,
            ControlErrorCode::MethodNotFound,
        ] {
            let failure =
                ControlFailure::Rejected(ControlError::of(code, "no valid control token"));
            let mapped = ChainReadError::from_open_read_failure(METHOD, failure);

            assert!(
                matches!(mapped, ChainReadError::Unsupported { .. }),
                "{code:?} must map to Unsupported, got {mapped:?}"
            );
            let sentence = mapped.to_string();
            assert!(
                sentence.contains("upgrade dig-node"),
                "{code:?} must name the upgrade remedy, said: {sentence}"
            );
            assert!(
                !sentence.to_lowercase().contains("token"),
                "{code:?} must not send anybody after a token, said: {sentence}"
            );
        }
    }

    /// **An HTTP 401, which arrives before any JSON-RPC body exists, reads the same way.**
    ///
    /// A separate case from the one above because it travels a different path: the node refuses at
    /// the HTTP layer, so there is no `data.code` to key off at all. A mapping that only handled the
    /// JSON-RPC arm would leave this one falling into `Transport`, whose remedy is "retry" — an
    /// endless retry against a node that will never serve the method.
    #[test]
    fn an_http_401_on_an_open_read_says_upgrade_not_retry() {
        let mapped = ChainReadError::from_open_read_failure(
            METHOD,
            ControlFailure::Transport(ControlCallError::HttpRefused {
                code: 401,
                detail: "unauthorized control request".into(),
            }),
        );
        assert!(
            matches!(mapped, ChainReadError::Unsupported { .. }),
            "{mapped:?}"
        );
        assert!(mapped.to_string().contains("upgrade dig-node"));
    }

    /// **A node that says it could not answer is a `Transport` failure, never an `Unsupported` one.**
    ///
    /// `WALLET_READ_FAILED` and its siblings mean the node exists, knows the method, and could not
    /// reach a chain. The remedy is to retry, and telling somebody to upgrade instead would have
    /// them replace a working node over a dropped connection. Paired with the two tests above, this
    /// keeps all three remedies distinguishable rather than merely present.
    #[test]
    fn a_node_that_could_not_answer_is_a_retryable_transport_failure() {
        let mapped = ChainReadError::from_open_read_failure(
            METHOD,
            ControlFailure::Rejected(ControlError::of(
                ControlErrorCode::WalletReadFailed,
                "the chain source timed out",
            )),
        );
        assert!(
            matches!(mapped, ChainReadError::Transport { .. }),
            "{mapped:?}"
        );
        assert!(!mapped.to_string().contains("upgrade"));
    }

    /// **An unreachable node is a `Transport` failure and says so in the sentence.**
    #[test]
    fn an_unreachable_node_is_a_transport_failure() {
        let mapped = ChainReadError::from_open_read_failure(
            METHOD,
            ControlFailure::Transport(ControlCallError::Unreachable("connection refused".into())),
        );
        assert!(
            matches!(mapped, ChainReadError::Transport { .. }),
            "{mapped:?}"
        );
        assert!(mapped.to_string().contains("connection refused"));
    }
}
