//! Discarding the node's cached coin database and re-syncing it from chain
//! (dig_ecosystem#3170, dig-app#295) — over `control.wallet.resetCoinDb`.
//!
//! # What this button is for
//!
//! One coin whose parent spend could not be fetched at ingest time is skipped, silently, and never
//! retried (dig-node#384). Nothing re-queues it, so it stays unattributed for the life of the
//! database and its value never reaches an asset-scoped balance. There is otherwise no way for a
//! user to recover from that short of deleting the file by hand. This module is the recovery: drop
//! the cache, let the replica rebuild it from chain.
//!
//! # No key material crosses here, and nothing is spent (§908)
//!
//! Every table the node clears is chain-derived and reproduced by syncing. A seed or key is never
//! touched, and no coin moves — the coins live on chain exactly as before; only this machine's local
//! copy of their history is discarded and rebuilt. `control.wallet.resetCoinDb` therefore takes no
//! signature and this module builds no spend.
//!
//! # The confirm flag is INTERNAL, never a caller's decision
//!
//! [`reset`](ControlResetCoinDb::reset) always sends `confirm: true` — the user's OWN confirmation
//! already happened in the [`ClaimPrompt`](crate::confirm::ClaimPrompt) the caller raised before
//! reaching this module. There is no path through this type that can omit it, so the "you forgot to
//! confirm" refusal the node's contract defines is unreachable from here by construction, not by
//! discipline.
//!
//! # Why a refusal is shown VERBATIM rather than classified
//!
//! [`reservations_control`](super::reservations_control) branches on the node's stable `data.code`
//! symbol precisely because prose is not contract-stable. `control.wallet.resetCoinDb` does not yet
//! offer that seam: dig-node answers BOTH "you forgot to confirm" and "a spend is in flight" as the
//! same `INVALID_PARAMS` symbol, differing only in message text
//! (`dig-node-control-interface`#48's own gap, tracked for a follow-up). Since this module never
//! sends an unconfirmed request, every `INVALID_PARAMS` it can actually receive back is the
//! spend-in-flight refusal in practice — but "in practice" is not a symbol, so [`ResetOutcome`]
//! reports the node's message untouched rather than manufacturing a classification this contract
//! cannot yet make honest. A person reads dig-node's own words ("N coin reservation(s) are in
//! flight… wait for them to confirm or expire") instead of a paraphrase that could drift from what
//! actually happened.

use std::time::Duration;

use dig_node_control_interface::error::ControlErrorCode;
use dig_node_control_interface::params::WalletResetCoinDbParams;

use crate::control::{self, ControlFailure};

/// How long the reset call may run before it is abandoned.
///
/// The reset itself is a bounded local DELETE, not the resync that follows it — the resync runs in
/// the background against [`crate::network::NetworkStanding`], read separately and continuously, the
/// same way every other sync-progress surface in this app already works. So this budget only needs
/// to cover the drop, not the rebuild: generous next to
/// [`RESERVATION_CALL_TIMEOUT`](super::reservations_control::RESERVATION_CALL_TIMEOUT) because a
/// full-table `DELETE` can take longer than a handful of in-memory reservation rows, short enough
/// that a wedged node costs a refused click rather than a frozen window.
pub const RESET_CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// What discarding the coin database actually produced.
///
/// Four outcomes, and they demand different remedies — the same reason
/// [`NodeTableError`](super::reservations::NodeTableError) is a type and not a string:
///
/// - [`Reset`](Self::Reset) — done; the caller re-reads sync status and shows "unknown" while it
///   rebuilds, never a confident zero (the money-lie class §2.6 forbids).
/// - [`Refused`](Self::Refused) — the node declined; there is a real reason, worth reading, and the
///   remedy is to wait and retry, never to hide the message.
/// - [`Unsupported`](Self::Unsupported) — this node predates the method entirely; the button should
///   not have been reachable, and the remedy is upgrading the node, never retrying.
/// - [`Unavailable`](Self::Unavailable) — no node answered at all, or its answer was unreadable; the
///   remedy is checking the node is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResetOutcome {
    /// The node dropped its cache and will re-sync. Counts are LOCAL cache rows discarded, never
    /// money lost — every one of them is reproduced by the re-sync that follows.
    Reset {
        /// Confirmed coin rows discarded.
        coins_dropped: u64,
        /// Staged (not-yet-confirmed) coin rows discarded.
        staged_dropped: u64,
    },
    /// The node declined, with its own reason verbatim — see the module doc for why this is prose
    /// rather than a classified reason.
    Refused(String),
    /// This node's build does not serve `control.wallet.resetCoinDb` at all.
    Unsupported,
    /// No node answered, or its answer could not be read.
    Unavailable(String),
}

/// The coin-database reset, reached over the loopback control plane.
///
/// Endpoint and token are resolved on every call rather than fixed at construction — the same
/// reason [`ControlReservationTable`](super::reservations_control::ControlReservationTable) does it:
/// the §5.3 ladder is re-resolved as the node comes and goes, and pinning an endpoint at start-up
/// would keep addressing a node that had moved.
pub struct ControlResetCoinDb {
    endpoint: Box<dyn Fn() -> Option<String> + Send + Sync>,
    token: Box<dyn Fn() -> Option<String> + Send + Sync>,
    timeout: Duration,
}

impl std::fmt::Debug for ControlResetCoinDb {
    /// Names the type without calling the resolvers from a `Debug` impl — see
    /// [`ControlReservationTable`](super::reservations_control::ControlReservationTable)'s identical
    /// reasoning: printing a resolved endpoint here would be a network round trip inside formatting.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlResetCoinDb")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl ControlResetCoinDb {
    /// A reset reached through the given endpoint/token resolvers.
    pub fn new(
        endpoint: impl Fn() -> Option<String> + Send + Sync + 'static,
        token: impl Fn() -> Option<String> + Send + Sync + 'static,
        timeout: Duration,
    ) -> Self {
        Self {
            endpoint: Box::new(endpoint),
            token: Box::new(token),
            timeout,
        }
    }

    /// The reset for the node this machine is running, resolved off the §5.3 ladder — the one-call
    /// wiring a binary uses, kept here rather than in the binary so the ladder resolution can never
    /// drift into a second copy of what every other control caller in this crate already does.
    pub fn for_host() -> Self {
        Self::new(
            || {
                let ladder = control::endpoint_ladder(None);
                let token = control::load_control_token();
                control::resolve_status(&ladder, token.as_deref(), control::DEFAULT_PROBE_TIMEOUT)
                    .ok()
                    .map(|(endpoint, _)| endpoint)
            },
            control::load_control_token,
            RESET_CALL_TIMEOUT,
        )
    }

    /// Discard the cache and re-sync. `confirm: true` is sent unconditionally — see the module doc.
    ///
    /// The CALLER's own [`ClaimPrompt`](crate::confirm::ClaimPrompt) is the user's consent; this
    /// method performs the action once that has already happened, and never asks a second time.
    pub fn reset(&self) -> ResetOutcome {
        let Some(endpoint) = (self.endpoint)() else {
            return ResetOutcome::Unavailable(
                "no dig-node answered, so the coin database could not be reset".to_owned(),
            );
        };
        let result = control::call_control_result(
            &endpoint,
            &WalletResetCoinDbParams { confirm: true },
            (self.token)().as_deref(),
            self.timeout,
        );
        classify(result)
    }
}

/// Turn the node's typed answer into the four outcomes this seam can act on.
///
/// Split from [`ControlResetCoinDb::reset`] so the mapping is reachable by a test without standing
/// up a node — the same split [`reservations_control::classify`](super::reservations_control) uses,
/// for the same reason.
fn classify(
    result: Result<dig_node_control_interface::results::WalletResetCoinDbResult, ControlFailure>,
) -> ResetOutcome {
    match result {
        Ok(r) => ResetOutcome::Reset {
            coins_dropped: r.coins_dropped,
            staged_dropped: r.staged_dropped,
        },
        // A node that resolves no such method has told us what it IS, definitively — never an
        // outage, and never worth retrying.
        Err(ControlFailure::Rejected(e))
            if e.data.code == ControlErrorCode::MethodNotFound.name()
                || e.data.code == ControlErrorCode::NotSupported.name() =>
        {
            ResetOutcome::Unsupported
        }
        // Every other rejection this module can reach IS the spend-in-flight refusal in practice
        // (see the module doc for why it is not classified more finely than that), so its message is
        // shown as the node wrote it rather than paraphrased.
        Err(ControlFailure::Rejected(e)) => ResetOutcome::Refused(e.message),
        Err(ControlFailure::Transport(e)) => ResetOutcome::Unavailable(e.to_string()),
    }
}

/// The confirmation prompt's fixed copy (dig-app#295's own wording, verbatim).
///
/// One confirmation, accurate in both directions per the ticket: understating it invites a casual
/// mid-spend click; overstating it ("reset wallet", a red danger dialog) frightens off the one user
/// who actually needs it. So it says exactly what happens and nothing more alarming.
pub mod copy {
    /// The window title.
    pub const TITLE: &str = "Reset coin database";
    /// The question being put to the user.
    pub const HEADING: &str = "Reset the coin database and re-sync?";
    /// What each answer does, in the user's words.
    pub const BODY: &str = "This re-downloads this wallet's coin history from the chain. Keys are untouched. Nothing on chain changes. It may take a while.";
    /// The affirming choice's label — a verb naming the action, not a bare "OK".
    pub const AFFIRM: &str = "Reset and re-sync";
}

/// Render one [`ResetOutcome`] as a follow-up notice: `(heading, body)`.
///
/// A pure function, deliberately, so its copy is testable without a native confirmer — the same
/// split [`copy`] itself exists for.
pub fn describe(outcome: &ResetOutcome) -> (&'static str, String) {
    match outcome {
        ResetOutcome::Reset {
            coins_dropped,
            staged_dropped,
        } => (
            "Reset started",
            format!(
                "Dropped {coins_dropped} confirmed and {staged_dropped} pending coin record(s). The wallet is re-syncing from chain now; balances will read as unknown until it catches up."
            ),
        ),
        ResetOutcome::Refused(why) => ("Could not reset yet", why.clone()),
        ResetOutcome::Unsupported => (
            "Not available on this node",
            "This dig-node does not yet serve a coin-database reset. Update it and try again."
                .to_owned(),
        ),
        ResetOutcome::Unavailable(why) => ("Could not reach the node", why.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_node_control_interface::error::{ControlError, ControlErrorData};
    use dig_node_control_interface::results::WalletResetCoinDbResult;

    /// A node error carrying `symbol` as its stable code — mirrors
    /// [`reservations_control::tests::rejected`](super::super::reservations_control).
    fn rejected(symbol: &str, message: &str) -> ControlFailure {
        ControlFailure::Rejected(ControlError {
            code: -32602,
            message: message.to_owned(),
            data: ControlErrorData {
                code: symbol.to_owned(),
                origin: "node".to_owned(),
            },
        })
    }

    /// **A success reports the node's own counts, byte-identical.**
    #[test]
    fn a_success_carries_the_dropped_counts_through_unmodified() {
        assert_eq!(
            classify(Ok(WalletResetCoinDbResult {
                coins_dropped: 7,
                staged_dropped: 2,
            })),
            ResetOutcome::Reset {
                coins_dropped: 7,
                staged_dropped: 2,
            }
        );
    }

    /// **`coins_dropped == 0` on an already-empty cache is still `Reset`, never a refusal.**
    ///
    /// Zero dropped rows means the cache was already empty, not that the reset failed to run — see
    /// [`WalletResetCoinDbResult`](dig_node_control_interface::results::WalletResetCoinDbResult)'s own
    /// doc. A caller collapsing this into an error would tell a user with a healthy, empty cache that
    /// their reset failed.
    #[test]
    fn zero_dropped_is_still_a_success() {
        assert_eq!(
            classify(Ok(WalletResetCoinDbResult {
                coins_dropped: 0,
                staged_dropped: 0,
            })),
            ResetOutcome::Reset {
                coins_dropped: 0,
                staged_dropped: 0,
            }
        );
    }

    /// **A node that has never heard of this method is `Unsupported`, never `Unavailable`.**
    ///
    /// The two demand opposite remedies: `Unavailable` says "try again", `Unsupported` says "upgrade
    /// the node" — collapsing them would send a person retrying a refusal no retry can fix.
    #[test]
    fn method_not_found_is_unsupported_not_unavailable() {
        assert_eq!(
            classify(Err(rejected("METHOD_NOT_FOUND", "no such method"))),
            ResetOutcome::Unsupported
        );
    }

    /// **`NOT_SUPPORTED` is ALSO `Unsupported`** — the second spelling an older/newer build may use
    /// for the same "this build does not serve it" fact.
    #[test]
    fn not_supported_is_also_unsupported() {
        assert_eq!(
            classify(Err(rejected("NOT_SUPPORTED", "disabled on this build"))),
            ResetOutcome::Unsupported
        );
    }

    /// **A spend-in-flight refusal is shown VERBATIM, never paraphrased or swallowed.**
    ///
    /// The node's own reservation count is only carried in the message today (dig-node-control-
    /// interface#48 has no distinct symbol yet — see the module doc), so the message IS the payload:
    /// dropping it would tell the user only "refused", with no path to the remedy ("wait").
    #[test]
    fn a_generic_rejection_is_shown_verbatim_not_swallowed() {
        let message = "refused: 3 coin reservation(s) are in flight. Wait for them to confirm or expire, then retry.";
        match classify(Err(rejected("INVALID_PARAMS", message))) {
            ResetOutcome::Refused(got) => assert_eq!(got, message),
            other => panic!("a refusal must carry the node's own words through, got {other:?}"),
        }
    }

    /// **No node reachable is `Unavailable`, carrying a human-readable reason.**
    #[test]
    fn a_transport_failure_is_unavailable() {
        match classify(Err(ControlFailure::Transport(
            crate::control::ControlCallError::BadResponse("timed out".into()),
        ))) {
            ResetOutcome::Unavailable(why) => assert!(why.contains("timed out")),
            other => panic!("a transport failure must read as unavailable, got {other:?}"),
        }
    }

    /// **The four outcomes are pairwise distinct** — a classifier that merged any two of them would
    /// still pass every test above in isolation; this is the property those tests individually
    /// cannot show.
    #[test]
    fn the_four_outcomes_are_pairwise_distinct() {
        let reset = ResetOutcome::Reset {
            coins_dropped: 1,
            staged_dropped: 0,
        };
        let refused = ResetOutcome::Refused("x".into());
        let unsupported = ResetOutcome::Unsupported;
        let unavailable = ResetOutcome::Unavailable("x".into());
        let all = [&reset, &refused, &unsupported, &unavailable];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(i == j, a == b, "outcomes at {i} and {j}");
            }
        }
    }

    /// **A success's notice names the counts the node reported, not a paraphrase of them.**
    #[test]
    fn describe_a_success_names_both_counts() {
        let (heading, body) = describe(&ResetOutcome::Reset {
            coins_dropped: 7,
            staged_dropped: 2,
        });
        assert_eq!(heading, "Reset started");
        assert!(body.contains('7') && body.contains('2'));
        assert!(
            body.contains("unknown"),
            "must warn the balance reads unknown during the resync, never imply a fresh zero: {body}"
        );
    }

    /// **A refusal's notice is the node's OWN words, not dig-app's paraphrase of them.**
    ///
    /// Same property [`a_generic_rejection_is_shown_verbatim_not_swallowed`] asserts one layer down;
    /// repeated here because `describe` is a second place the message could be silently reworded or
    /// dropped.
    #[test]
    fn describe_a_refusal_carries_the_nodes_message_verbatim() {
        let (_heading, body) = describe(&ResetOutcome::Refused("refused: 3 in flight".into()));
        assert_eq!(body, "refused: 3 in flight");
    }

    /// **The confirmation copy never uses alarming words the ticket explicitly warns against**
    /// ("reset wallet", "delete", "danger") — the overstating failure direction costs the one user
    /// who most needs to press it.
    #[test]
    fn confirm_copy_does_not_overstate_the_action() {
        let alarming = ["delete", "danger", "wallet reset", "wipe"];
        for word in alarming {
            assert!(
                !copy::BODY.to_lowercase().contains(word),
                "body must not say {word:?}: {}",
                copy::BODY
            );
        }
        assert!(copy::BODY.contains("Keys are untouched"));
        assert!(copy::BODY.contains("Nothing on chain changes"));
    }
}
