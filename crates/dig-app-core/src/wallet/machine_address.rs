//! Reading the machine wallet's address from the node — `control.wallet.operatorAddress`.
//!
//! [`super::machine`] holds what the app KNOWS about the machine wallet. This module is where that
//! knowledge comes from: one token-gated, node-local read, and the mapping of its answer onto
//! [`MachineAddressReading`].
//!
//! # This is the wiring step the module above predicted, not a second derivation
//!
//! [`super::machine`]'s own docs said the address must never be derived here — that a second,
//! independent derivation of a money address is the rival-implementation defect in its most
//! expensive form, because the two copies agree until the day they do not and on that day a person
//! funds an address nothing watches. That still holds. **The node names the address; this module
//! only asks.** Nothing here computes a puzzle hash, decodes a bech32m string, or turns a seed into
//! anything.
//!
//! # Every absence keeps its own reason, and one of them is not a fault
//!
//! The contract answers with two shapes and this app renders four, so the mapping is where a real
//! distinction can be lost. The one that matters most is
//! [`WalletOperatorAddressUnavailableReason::NotInitialized`]: the contract states outright that a
//! client MUST NOT present it as a fault, because a node that has not run its autoseed setup simply
//! has no operator wallet yet and will have one. Folding it into
//! [`MachineAddressUnknown::ReadFailed`] would tell a person their machine custody is broken when
//! nothing is wrong, and folding it into [`MachineAddressUnknown::NotPublished`] would tell them
//! their node is too old when it is new enough to have answered the question.
//!
//! # Nothing privileged crosses here (§908)
//!
//! The request carries no parameters and the response carries an address and a puzzle hash. Both
//! are public in exactly the sense a coin id is: they say WHERE money can be sent, never HOW it can
//! be spent. The user's own key is not involved in this read in any direction.

use std::time::Duration;

use dig_node_control_interface::params::WalletOperatorAddressParams;
use dig_node_control_interface::results::{
    WalletOperatorAddressResult, WalletOperatorAddressUnavailableReason,
};
use dig_node_control_interface::traits::ControlCall;

use crate::activity::absence::ControlAbsence;
use crate::control;

use super::machine::{MachineAddressReading, MachineAddressUnknown};

/// How long one operator-address read may take before it is abandoned.
///
/// The same budget the bond-state read uses, for the same reason: this is a node-local answer over
/// the loopback rather than a chain round trip, so a longer wait buys nothing but a frozen pane.
pub const ADDRESS_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The method that names the node's own operator wallet.
///
/// Taken from the contract's own [`ControlCall`] impl, so the one method string in this module is
/// not one this app can spell wrong.
pub fn method() -> &'static str {
    <WalletOperatorAddressParams as ControlCall>::METHOD.name()
}

/// Ask the node where its own operator wallet receives.
///
/// Returns a [`MachineAddressReading`] rather than a `Result`, so no caller can turn an outage into
/// an address — which on this surface would be a destination somebody sends real money to.
///
/// The RAW call is used for the reason [`crate::activity::bonds::read`] uses it: the typed helper
/// reports a decode failure as a transport error, which would render *DIG could not reach your
/// node* about a node that answered.
pub fn read(
    endpoint: Option<&str>,
    token: Option<&str>,
    timeout: Duration,
) -> MachineAddressReading {
    let Some(endpoint) = endpoint else {
        return MachineAddressReading::Unknown(MachineAddressUnknown::NoNode);
    };
    let params = serde_json::to_value(WalletOperatorAddressParams {})
        .expect("the contract params type is plain data and always serializes");
    match control::call_control_raw(endpoint, method(), params, token, timeout) {
        Ok(value) => match serde_json::from_value::<WalletOperatorAddressResult>(value) {
            Ok(result) => address_from(result),
            // A node that answered with something undecodable said something; quoting the shape of
            // the failure beats a category chosen here.
            Err(why) => MachineAddressReading::Unknown(MachineAddressUnknown::ReadFailed(format!(
                "Your node answered with an address DIG could not read: {why}"
            ))),
        },
        Err(failure) => MachineAddressReading::Unknown(ControlAbsence::of(&failure).into()),
    }
}

/// Map the contract's answer onto this app's reading.
///
/// Split out from the transport so the whole decision is testable without a socket — and because
/// this, not the HTTP, is where a money address can quietly become the wrong one.
fn address_from(result: WalletOperatorAddressResult) -> MachineAddressReading {
    match result {
        // `puzzle_hash` is deliberately dropped. This surface shows an address a person copies, and
        // carrying a second spelling of the same destination would give the pane two values it
        // could disagree about. A consumer that must match coins against this wallet re-reads the
        // method; it does not get a half-remembered hash from here.
        WalletOperatorAddressResult::Known { address, .. } => MachineAddressReading::Known(address),
        WalletOperatorAddressResult::Unavailable { reason } => {
            MachineAddressReading::Unknown(match reason {
                WalletOperatorAddressUnavailableReason::NotInitialized => {
                    MachineAddressUnknown::NotInitialized
                }
                WalletOperatorAddressUnavailableReason::Unreadable => {
                    MachineAddressUnknown::ReadFailed(
                        "Your node has an operator wallet it cannot read, so it cannot pay for \
                         collateral either."
                            .to_string(),
                    )
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlFailure;
    use dig_node_control_interface::error::{ControlError, ControlErrorCode, ControlErrorData};

    /// The address the node names is the address this app carries, unchanged.
    #[test]
    fn a_known_answer_carries_the_nodes_own_address_verbatim() {
        let reading = address_from(WalletOperatorAddressResult::Known {
            address: "xch1machinewallet".to_string(),
            puzzle_hash: "aa".repeat(32),
        });
        assert_eq!(
            reading,
            MachineAddressReading::Known("xch1machinewallet".to_string()),
            "the address a person sends money to must be the node's own words"
        );
    }

    /// A node that has not created its operator wallet yet is not a node with a broken one, and it
    /// is not a node too old to answer either.
    ///
    /// The contract says in as many words that a client MUST NOT present `NotInitialized` as a
    /// fault. Both nearest wrong answers are ruled out by name rather than by asserting only the
    /// right one, because the failure this pins is a mapping collapsing into a neighbour — and an
    /// assertion that names only the intended variant passes just as happily when the variant it
    /// was supposed to displace is the one that survived.
    #[test]
    fn an_uninitialised_operator_wallet_is_neither_a_fault_nor_an_old_node() {
        let reading = address_from(WalletOperatorAddressResult::Unavailable {
            reason: WalletOperatorAddressUnavailableReason::NotInitialized,
        });
        assert_eq!(
            reading,
            MachineAddressReading::Unknown(MachineAddressUnknown::NotInitialized),
            "a node still setting itself up has its own state"
        );
        assert_ne!(
            reading,
            MachineAddressReading::Unknown(MachineAddressUnknown::NotPublished),
            "NotPublished says the node is too old; this node answered the method"
        );
        assert!(
            !matches!(
                reading,
                MachineAddressReading::Unknown(MachineAddressUnknown::ReadFailed(_))
            ),
            "the contract states a client MUST NOT present NotInitialized as a fault"
        );
    }

    /// An operator wallet the node cannot read IS a fault, and the sentence says so.
    #[test]
    fn an_unreadable_operator_wallet_is_reported_as_the_fault_it_is() {
        let reading = address_from(WalletOperatorAddressResult::Unavailable {
            reason: WalletOperatorAddressUnavailableReason::Unreadable,
        });
        let MachineAddressReading::Unknown(MachineAddressUnknown::ReadFailed(said)) = reading
        else {
            panic!("an unreadable operator wallet is a fault, not an absence: {reading:?}");
        };
        assert!(
            said.contains("cannot read"),
            "the sentence must name what failed, said: {said}"
        );
    }

    /// The two unavailable reasons must not render as the same state.
    ///
    /// Their remedies are opposite — one is *wait, nothing is wrong* and the other is *your node's
    /// machine custody is broken* — so a mapping that collapses them is a wrong instruction, not a
    /// lost nuance.
    #[test]
    fn the_two_unavailable_reasons_stay_distinct() {
        let not_initialised = address_from(WalletOperatorAddressResult::Unavailable {
            reason: WalletOperatorAddressUnavailableReason::NotInitialized,
        });
        let unreadable = address_from(WalletOperatorAddressResult::Unavailable {
            reason: WalletOperatorAddressUnavailableReason::Unreadable,
        });
        assert_ne!(not_initialised, unreadable);
    }

    /// With no endpoint nothing was asked, and an unasked question has no answer.
    #[test]
    fn no_endpoint_is_no_node_rather_than_a_missing_address() {
        assert_eq!(
            read(None, None, ADDRESS_READ_TIMEOUT),
            MachineAddressReading::Unknown(MachineAddressUnknown::NoNode)
        );
    }

    /// A control rejection carrying `code` in its stable symbol slot.
    fn rejected(code: &str) -> ControlFailure {
        ControlFailure::Rejected(ControlError {
            code: -32601,
            message: "no".to_string(),
            data: ControlErrorData {
                code: code.to_string(),
                origin: "node".to_string(),
            },
        })
    }

    /// A node too old to serve the method is reported as too old, not as a broken wallet.
    #[test]
    fn a_node_without_the_method_is_too_old_rather_than_faulty() {
        let absence: MachineAddressUnknown =
            ControlAbsence::of(&rejected(ControlErrorCode::MethodNotFound.name())).into();
        assert_eq!(absence, MachineAddressUnknown::NotPublished);
    }

    /// The method string is the contract's, not one spelled here.
    #[test]
    fn the_method_is_the_contracts_own_name() {
        assert_eq!(method(), "control.wallet.operatorAddress");
    }
}
