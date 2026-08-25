//! The reservation table over the loopback control plane — `control.wallet.reservations.*`.
//!
//! `reservations` decides what a reservation MEANS; this module is only how the question
//! reaches dig-node and how its answer comes back. The split matters because the two fail in
//! different ways: a wrong policy is a double-select, while a wrong mapping here turns a node that
//! is merely busy into one that appears to hold nothing.
//!
//! # The answers, which must never collapse into fewer
//!
//! | node says | becomes | the person is told |
//! |---|---|---|
//! | `WALLET_COINS_RESERVED` (`-32046`) | `Conflict` | those coins are busy — wait |
//! | `WALLET_RESERVATIONS_UNAVAILABLE` (`-32047`) | `Unavailable` | the node could not tell us; nothing was built |
//! | `METHOD_NOT_FOUND` / `NOT_SUPPORTED` | `Unsupported` | nothing — the scope quietly narrows |
//! | anything else, or no answer at all | `Unavailable` | the node could not tell us |
//!
//! # Branch on the SYMBOL, never on the numeric code or its band
//!
//! The numbers are not stable and the band is not a disposition. `-32044` named
//! `WALLET_COINS_RESERVED` in the 0.20 contract and names `WALLET_NODE_SPEND_DISABLED` in 0.21 —
//! **opposite** dispositions, a wait against a terminal refusal. A client keyed off the number would
//! have kept retrying a refusal that no retry can fix, and it would have done so silently, because
//! both readings compile and neither is a parse error.
//!
//! The `-3204x` band is likewise not one meaning: `-32046` is a WAIT, `-32047` is an UNKNOWN, and
//! `-32044` is TERMINAL. So every match here is on `data.code`, the stable UPPER_SNAKE symbol, and
//! the numbers appear only in this comment.
//!
//! An empty `reserved: []` is none of those: it is a positive statement that NOTHING is held, and it
//! is the one answer on which a caller may select freely. Rendering an outage as an empty list is
//! the failure this whole seam exists to prevent, so the two are kept structurally apart — an
//! unreachable node cannot reach the code path that produces a list.
//!
//! # No key material crosses here (§908)
//!
//! A coin id is a public chain fact and a reservation handle is an opaque token the node minted.
//! There is no seed, key, signature or bundle in any of these three calls, and there never may be:
//! reservation is BOOKKEEPING — it narrows what a selector will choose and authorizes nothing.

use std::sync::Arc;
use std::time::Duration;

use chia_protocol::Bytes32;
use dig_node_control_interface::error::ControlErrorCode;
use dig_node_control_interface::params::{
    WalletReservationsHeldParams, WalletReservationsReleaseParams, WalletReservationsReserveParams,
};
use dig_node_control_interface::results::ReservedCoin;
use dig_node_control_interface::traits::ControlCall;

use crate::control::{self, ControlFailure};

use super::reservations::{
    HeldCoin, NodeHeld, NodeHold, NodeReservationTable, NodeReservations, NodeTableError,
};

/// How long one reservation call may take before it is abandoned.
///
/// Reservation is a local table read, not a chain read, so it is nothing like
/// [`super::node::BALANCE_READ_TIMEOUT`] — that budget is sized for a node that may go out to a
/// public HTTPS chain source. Five seconds is generous for a lookup in memory and short enough that
/// a wedged node costs a refused build rather than a frozen one. Refusing is safe here; waiting is
/// what a person notices.
pub const RESERVATION_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// dig-node's reservation table, reached over the control plane.
///
/// # Why the endpoint is resolved per call rather than fixed
///
/// The store behind this is a process singleton installed once at start-up, but the node it talks
/// to is not fixed for the life of the process: the §5.3 ladder is re-resolved as the node comes and
/// goes, and dig-app is running long before any node answers. A table pinned to whatever endpoint
/// existed at start-up would keep addressing a node that had moved — and a handle released against
/// the wrong node frees nothing, which strands the user's coins for the full TTL.
///
/// So the endpoint is a resolver, called on every request. The cost is one resolution per
/// reservation call; the alternative is a table that silently stops working after a node restart.
pub struct ControlReservationTable {
    endpoint: Box<dyn Fn() -> Option<String> + Send + Sync>,
    token: Box<dyn Fn() -> Option<String> + Send + Sync>,
    timeout: Duration,
}

impl std::fmt::Debug for ControlReservationTable {
    /// Names the type without pretending its resolvers are inspectable.
    ///
    /// Printing a resolved endpoint here would call the ladder from a `Debug` impl, which is a
    /// network round trip inside a formatting call.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlReservationTable")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl ControlReservationTable {
    /// A table whose node is resolved by `endpoint` and authorized by `token`, on every call.
    ///
    /// All three methods are TOKEN-GATED, including `held` — the caller supplies nothing, so the
    /// answer is the node's own state rather than a lookup on the caller's behalf. Without a token
    /// every call refuses, which is the correct fail direction: it becomes
    /// [`NodeTableError::Unavailable`] and refuses the build, rather than an empty held set that
    /// would read as a healthy wallet with nothing in flight.
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

    /// The table for the node this machine is running, resolved off the §5.3 ladder.
    ///
    /// The one-call wiring a binary uses. It is here rather than in the binary because a binary is a
    /// test-free zone, and because the ladder resolution is the same one every other control caller
    /// in this crate already uses — a second copy of it would be a rival that could drift.
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
            RESERVATION_CALL_TIMEOUT,
        )
    }

    /// One control call, with the node's typed error mapped onto this seam's two outcomes.
    fn call<C: ControlCall>(&self, call: &C) -> Result<C::Output, NodeTableError> {
        // No node answered the ladder. That is an OUTAGE, not a node that serves no reservation
        // table: a node may well appear a moment later, so this must refuse rather than degrade the
        // scope for the rest of the session.
        let Some(endpoint) = (self.endpoint)() else {
            return Err(NodeTableError::Unavailable(
                "no dig-node answered, so what is in flight cannot be read".to_owned(),
            ));
        };
        control::call_control_result(&endpoint, call, (self.token)().as_deref(), self.timeout)
            .map_err(classify)
    }
}

/// The reservation STORE this machine should install, ready to hand to
/// [`install`](super::reservations::install).
///
/// The whole wiring in one call, so a binary — a test-free zone — never assembles it by hand and
/// cannot get the layering wrong: the transport is a [`ControlReservationTable`], and the policy
/// (authority, fail direction, release backlog, degraded mode) is [`NodeReservations`].
pub fn store_for_host() -> NodeReservations {
    NodeReservations::new(Arc::new(ControlReservationTable::for_host()))
}

/// Turn a control failure into the two things this seam can act on.
///
/// Keyed off the stable `data.code` symbol rather than the numeric code or the human message: the
/// message is explicitly not contract-stable, and matching on prose is how a node that rewords an
/// error silently turns a conflict into an outage.
fn classify(failure: ControlFailure) -> NodeTableError {
    match failure {
        ControlFailure::Rejected(error)
            if error.data.code == ControlErrorCode::WalletCoinsReserved.name() =>
        {
            // Deliberately drops the message. The contract's error data is `{code, origin}` and
            // carries no coin id, so there is nothing here to attribute the clash with — the caller
            // re-reads `.held` and intersects. See `NodeReservations::attribute_conflict`.
            NodeTableError::Conflict
        }
        // A node that resolves no such method has told us what it IS, definitively. Treating that
        // as an outage would refuse every send against every node built before the reservation
        // contract — permanently, since no retry can fix a method that does not exist.
        ControlFailure::Rejected(error)
            if error.data.code == ControlErrorCode::MethodNotFound.name()
                || error.data.code == ControlErrorCode::NotSupported.name() =>
        {
            NodeTableError::Unsupported
        }
        // Terminal, and NOT a reservation outcome at all: the node refuses to broadcast a bundle
        // that spends its own coins. It reaches this seam only if a node returns it from a
        // reservation call, which the contract does not sanction — so it is refused rather than
        // trusted. Named explicitly so it can never be mistaken for the WAIT that
        // `WALLET_COINS_RESERVED` is; the two were spelled `-32044` in successive contract versions.
        ControlFailure::Rejected(error)
            if error.data.code == ControlErrorCode::WalletNodeSpendDisabled.name() =>
        {
            NodeTableError::Unavailable(format!(
                "the node refused the reservation as a disabled spend, which retrying cannot fix: {}",
                error.message
            ))
        }
        ControlFailure::Rejected(error) => NodeTableError::Unavailable(error.message),
        ControlFailure::Transport(e) => NodeTableError::Unavailable(e.to_string()),
    }
}

/// Read a coin id the node sent as lowercase 64-hex.
///
/// A row this build cannot parse makes the WHOLE answer unusable rather than being skipped. Skipping
/// it would silently shrink the held set — the under-report that restores the double-select — and it
/// would do so most readily against a NEWER node, which is exactly when trusting the answer is least
/// safe.
fn coin_id(raw: &str) -> Result<Bytes32, NodeTableError> {
    let unusable = || {
        NodeTableError::Unavailable(format!(
            "the node reported a reserved coin id this build cannot read: {raw}"
        ))
    };
    let bytes = hex::decode(raw.strip_prefix("0x").unwrap_or(raw)).map_err(|_| unusable())?;
    Ok(Bytes32::new(
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| unusable())?,
    ))
}

/// Decode every reserved row, or none of them.
///
/// Separate from [`ControlReservationTable::held`] so the all-or-nothing property is reachable by a
/// test without standing up a node. `held` is a network call and a `bin`-adjacent path; this is
/// where the decision lives, and it is the decision that matters — a `filter_map` here would
/// silently shrink the held set, and an under-reported held set is the one direction that restores
/// the double-select.
fn decode_reserved(rows: &[ReservedCoin]) -> Result<Vec<HeldCoin>, NodeTableError> {
    rows.iter()
        .map(|row| {
            Ok(HeldCoin {
                coin_id: coin_id(&row.coin_id)?,
                // Kept, not discarded. This handle is the only way to release a hold whose `reserve`
                // reply was lost in transit; without it that coin is stranded until its TTL, once
                // per attempt.
                reservation_id: row.reservation_id.clone(),
                expires_at_unix: row.expires_at_unix,
            })
        })
        .collect()
}

impl NodeReservationTable for ControlReservationTable {
    fn held(&self) -> Result<NodeHeld, NodeTableError> {
        let result = self.call(&WalletReservationsHeldParams {})?;
        Ok(NodeHeld {
            reserved: decode_reserved(&result.reserved)?,
            as_of_unix: result.as_of_unix,
        })
    }

    fn reserve_all(&self, coins: &[Bytes32], ttl_secs: u64) -> Result<NodeHold, NodeTableError> {
        let result = self.call(&WalletReservationsReserveParams {
            coin_ids: coins.iter().map(hex::encode).collect(),
            ttl_secs: Some(ttl_secs),
        })?;
        Ok(NodeHold {
            reservation_id: result.reservation_id,
            // The node's applied lifetime, carried through verbatim. Substituting the requested one
            // here would defeat the entire reason the contract returns it.
            ttl_secs: result.ttl_secs,
            expires_at_unix: result.expires_at_unix,
        })
    }

    fn release(&self, reservation_id: &str) -> Result<(), NodeTableError> {
        // `released: false` is a SUCCESS: the handle named no live reservation, because the TTL got
        // there first or somebody released it already. Both are the outcome the caller wanted, and
        // reporting them as failures would teach callers to ignore the result — which is how the
        // release path quietly stops being used and every hold starts costing its full TTL.
        self.call(&WalletReservationsReleaseParams {
            reservation_id: reservation_id.to_owned(),
        })
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_node_control_interface::error::{ControlError, ControlErrorData};

    /// A node error carrying `symbol` as its stable code.
    ///
    /// The numeric code is deliberately FIXED at `-32044` for every fixture, whatever the symbol
    /// says. That is what makes these tests able to see a classifier that branches on the number:
    /// under 0.21 `-32044` is `WALLET_NODE_SPEND_DISABLED`, so a number-keyed implementation would
    /// give every fixture here the terminal disposition.
    fn rejected(symbol: &str, message: &str) -> ControlFailure {
        ControlFailure::Rejected(ControlError {
            code: -32044,
            message: message.to_owned(),
            data: ControlErrorData {
                code: symbol.to_owned(),
                origin: "node".to_owned(),
            },
        })
    }

    /// A busy coin is a CONFLICT — the answer that means "wait", not "the node is down".
    #[test]
    fn coins_reserved_is_a_conflict() {
        assert_eq!(
            classify(rejected("WALLET_COINS_RESERVED", "coins are held")),
            NodeTableError::Conflict
        );
    }

    /// An unreadable reservation set is UNAVAILABLE — a third thing, and never a conflict.
    ///
    /// Collapsing it into `Conflict` would tell a person to wait for a hold that does not exist, and
    /// dig-account would retry against an exclusion set built from a coin nobody named.
    #[test]
    fn an_unreadable_set_is_unavailable_and_not_a_conflict() {
        match classify(rejected(
            "WALLET_RESERVATIONS_UNAVAILABLE",
            "the reservation set could not be read",
        )) {
            NodeTableError::Unavailable(why) => assert!(why.contains("could not be read")),
            other => {
                panic!("an outage is neither a claim about a coin nor a capability: {other:?}")
            }
        }
    }

    /// The symbol decides, not the numeric code beside it.
    ///
    /// Every fixture carries `-32044`, which under 0.21 is `WALLET_NODE_SPEND_DISABLED` — terminal.
    /// A classifier keyed off the number would give all of them that disposition, so a
    /// symbol-keyed one is the only implementation that can pass this together with the conflict
    /// test above.
    #[test]
    fn the_stable_symbol_decides_rather_than_the_numeric_code() {
        assert!(matches!(
            classify(rejected("UNAUTHORIZED", "no token")),
            NodeTableError::Unavailable(_)
        ));
    }

    /// A code whose SYMBOL moved between contract versions keeps its meaning, not its number.
    ///
    /// `-32044` named `WALLET_COINS_RESERVED` in the 0.20 contract and names
    /// `WALLET_NODE_SPEND_DISABLED` in 0.21 — a WAIT and a TERMINAL refusal, exact opposites. A
    /// client that conflated them would retry forever against a refusal no retry can fix.
    ///
    /// The two assertions must disagree, on fixtures whose numeric codes are IDENTICAL. That is the
    /// property; either one alone is satisfiable by a constant.
    #[test]
    fn a_disabled_spend_is_terminal_and_never_the_wait_that_reserved_coins_are() {
        let disabled = classify(rejected(
            "WALLET_NODE_SPEND_DISABLED",
            "live broadcast is off",
        ));
        let busy = classify(rejected("WALLET_COINS_RESERVED", "coins are held"));

        assert_eq!(busy, NodeTableError::Conflict, "reserved coins are a WAIT");
        assert!(
            matches!(disabled, NodeTableError::Unavailable(_)),
            "a disabled spend is terminal and must never read as a wait: {disabled:?}"
        );
        assert_ne!(
            disabled, busy,
            "the two dispositions must not collapse; they shared the number -32044 across versions"
        );
    }

    /// An unknown symbol from a newer node is UNAVAILABLE, never a conflict.
    ///
    /// Refusing is the safe direction for a code this build has never seen: treating an unknown
    /// refusal as a conflict would make dig-account retry forever against a coin nobody named.
    #[test]
    fn an_unknown_symbol_refuses() {
        assert!(matches!(
            classify(rejected("SOME_FUTURE_CODE", "?")),
            NodeTableError::Unavailable(_)
        ));
    }

    /// A row this build cannot read fails the WHOLE answer, alongside rows that are fine.
    ///
    /// The mixed list is the load-bearing part. Asserting on `coin_id` alone, or on a list of one
    /// bad row, passes just as well for a `filter_map` that drops the bad row and returns the good
    /// ones — which silently shrinks the held set, and an under-reported held set is exactly the
    /// under-report that restores the double-select. A mutation to `filter_map` survived the
    /// single-row version of this test.
    #[test]
    fn one_unreadable_row_fails_the_whole_answer_rather_than_being_dropped() {
        let good = "ab".repeat(32);
        let rows = vec![
            ReservedCoin {
                coin_id: good.clone(),
                reservation_id: "node-1".to_owned(),
                expires_at_unix: 1_800_000_300,
            },
            ReservedCoin {
                coin_id: "not-a-coin-id".to_owned(),
                reservation_id: "node-2".to_owned(),
                expires_at_unix: 1_800_000_300,
            },
        ];

        match decode_reserved(&rows) {
            Err(NodeTableError::Unavailable(why)) => assert!(why.contains("cannot read")),
            Ok(decoded) => panic!(
                "an unreadable row must not be silently dropped; got {} of {} rows",
                decoded.len(),
                rows.len()
            ),
            other => panic!("expected an unusable answer: {other:?}"),
        }
    }

    /// The control: a list of readable rows decodes in full, in order.
    ///
    /// Without it, an implementation that failed on EVERY answer would pass the test above.
    #[test]
    fn readable_rows_decode_in_full() {
        let rows: Vec<ReservedCoin> = ["ab", "cd", "ef"]
            .iter()
            .map(|tag| ReservedCoin {
                coin_id: tag.repeat(32),
                reservation_id: "node-1".to_owned(),
                expires_at_unix: 1_800_000_300,
            })
            .collect();

        let decoded = decode_reserved(&rows).expect("every row is readable");
        assert_eq!(decoded.len(), 3, "no row may be dropped from a good answer");
        assert_eq!(
            decoded[0].coin_id,
            coin_id(&"ab".repeat(32)).expect("first row")
        );
        assert_eq!(
            decoded[0].reservation_id, "node-1",
            "the handle must survive decoding; it is the only way to release a hold whose reserve              reply was lost"
        );
    }

    /// A `0x` prefix is tolerated on input, as the contract says it is.
    #[test]
    fn a_prefixed_coin_id_is_accepted() {
        let bare = "ab".repeat(32);
        assert_eq!(
            coin_id(&format!("0x{bare}")).expect("prefixed"),
            coin_id(&bare).expect("bare")
        );
    }

    /// A node that resolves no such method is UNSUPPORTED, not unavailable.
    ///
    /// The difference decides whether every send against every pre-contract node refuses forever.
    /// No retry can conjure a method that does not exist, so an outage reading would be permanent.
    #[test]
    fn a_node_without_the_methods_is_unsupported_rather_than_down() {
        assert_eq!(
            classify(rejected("METHOD_NOT_FOUND", "no such method")),
            NodeTableError::Unsupported
        );
        assert_eq!(
            classify(rejected("NOT_SUPPORTED", "not on this build")),
            NodeTableError::Unsupported
        );
    }

    /// No node on the ladder is an OUTAGE, and never a node that serves no table.
    ///
    /// Degrading here would drop the cross-process guarantee for the whole session because dig-app
    /// happened to start before dig-node did — which is the ordinary case on a cold boot.
    #[test]
    fn no_node_on_the_ladder_refuses_without_degrading() {
        let table = ControlReservationTable::new(
            || None,
            || Some("token".to_owned()),
            Duration::from_millis(50),
        );
        match table.held() {
            Err(NodeTableError::Unavailable(why)) => assert!(why.contains("no dig-node answered")),
            other => panic!("an absent node is an outage: {other:?}"),
        }
    }
}
