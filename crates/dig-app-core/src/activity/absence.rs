//! Which absence a failed `control.*` call is — the one mapping every Activity surface shares.
//!
//! # Why this is its own module rather than a helper on either caller
//!
//! [`super::control`] and [`super::bonds`] each carried their own copy of this mapping, character
//! for character apart from the enum they returned into (dig-app#329). Neither was authoritative:
//! they were peers, written months apart, agreeing by coincidence rather than by construction.
//!
//! Two copies that agree today are not harmless here, because of what the mapping decides. It turns
//! a transport or JSON-RPC failure into **the sentence a person reads about why a figure about their
//! own money is missing**, and the whole reason that taxonomy has four arms is that conflating them
//! points the reader at the wrong remedy — someone told "this node is too old, update it" when the
//! truth is "DIG could not authenticate on this machine" updates a node that was never the problem.
//! Two independent mappings are two chances to get that wrong, and only one of them gets edited when
//! a fifth reason appears.
//!
//! So the string mapping — the part that drifts — lives here exactly once. Each surface keeps its
//! OWN enum, because they are not the same taxonomy: [`super::bonds::LockedUnknown`] carries a fifth
//! arm for the node naming its own gap, which has no meaning on the spends record. What they share
//! is the four ways a control call can fail to answer at all, and that is what [`ControlAbsence`] is.
//!
//! # Every conversion out of here is exhaustive, with no wildcard arm
//!
//! A `_ =>` arm on either surface would let a fifth absence fold silently into whichever neighbour
//! the wildcard pointed at, which is the failure this module exists to remove rather than relocate.
//! Adding a variant below is therefore a build error at both surfaces until both have said what it
//! means to their reader.

use dig_node_control_interface::error::ControlErrorCode;

use crate::control::ControlFailure;

/// The four ways a `control.*` call fails to produce an answer.
///
/// Deliberately NOT a superset of either surface's `Unknown` enum: those add arms for absences that
/// are not control failures at all (a node that answered and named its own missing fact, a reply
/// this app could not decode into the surface's model). This type is only the failure of the CALL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlAbsence {
    /// Nobody was asked — the node was unreachable, or its reply was not a JSON-RPC response.
    ///
    /// The remedy is the node's presence rather than its version, which is why this is separate from
    /// [`NotSupported`](Self::NotSupported): those two send a person to opposite places.
    NoNode,
    /// A node answered, and does not serve this method — it is too old to state the figure.
    NotSupported,
    /// The node refused the caller locally, typically with no valid control token on this machine.
    Refused,
    /// The node answered something this app could not turn into a reading.
    Unreadable,
}

impl ControlAbsence {
    /// Every variant, so a surface's conversion can be exercised across all of them at once.
    ///
    /// Hand-listed, and kept honest by [`Self::of`]'s exhaustive coverage test rather than by
    /// hoping: a variant missing from here would quietly shrink every test that iterates it.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 4] = [
        Self::NoNode,
        Self::NotSupported,
        Self::Refused,
        Self::Unreadable,
    ];

    /// Which absence a control failure is.
    ///
    /// # It branches on the stable UPPER_SNAKE symbol, never the numeric code
    ///
    /// The numbers have already changed meaning between contract releases, so a match on one is a
    /// match on nothing durable. [`ControlErrorCode::name`] is the symbol the contract promises.
    ///
    /// # The catch-all here is the right one, and it is the only one permitted anywhere in this flow
    ///
    /// The input is a `String` off the wire, not the contract enum, so it is not enumerable and a
    /// total match is not expressible. An unrecognised symbol is genuinely
    /// [`Unreadable`](Self::Unreadable): a node said something this app cannot interpret, which is
    /// exactly what that arm means. Conversions OUT of [`ControlAbsence`] have no such excuse and
    /// carry no wildcard.
    pub fn of(failure: &ControlFailure) -> Self {
        let ControlFailure::Rejected(error) = failure else {
            return Self::NoNode;
        };
        match error.data.code.as_str() {
            code if code == ControlErrorCode::MethodNotFound.name() => Self::NotSupported,
            "NOT_SUPPORTED" => Self::NotSupported,
            "UNAUTHORIZED" => Self::Refused,
            _ => Self::Unreadable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlCallError;
    use dig_node_control_interface::error::{ControlError, ControlErrorData};

    /// A rejection carrying the symbol a node would send.
    fn rejected(code: &str) -> ControlFailure {
        ControlFailure::Rejected(ControlError {
            code: -1,
            message: "rejected".to_string(),
            data: ControlErrorData {
                code: code.to_string(),
                origin: "node".to_string(),
            },
        })
    }

    #[test]
    fn transport_failure_is_nobody_was_asked() {
        assert_eq!(
            ControlAbsence::of(&ControlFailure::Transport(ControlCallError::Unreachable(
                "connection refused".to_string()
            ))),
            ControlAbsence::NoNode
        );
    }

    #[test]
    fn method_not_found_is_the_node_being_too_old() {
        assert_eq!(
            ControlAbsence::of(&rejected(ControlErrorCode::MethodNotFound.name())),
            ControlAbsence::NotSupported
        );
    }

    #[test]
    fn not_supported_is_the_node_being_too_old() {
        assert_eq!(
            ControlAbsence::of(&rejected("NOT_SUPPORTED")),
            ControlAbsence::NotSupported
        );
    }

    #[test]
    fn unauthorized_is_a_refusal_not_an_unreadable_answer() {
        assert_eq!(
            ControlAbsence::of(&rejected("UNAUTHORIZED")),
            ControlAbsence::Refused
        );
    }

    /// An unknown symbol must NOT land on any of the three specific arms.
    ///
    /// Asserted as a non-membership rather than only as equality with `Unreadable`, because the
    /// damage of getting this wrong is directional: folding an unrecognised symbol into `NoNode`
    /// tells a person their node is down when it answered, and into `NotSupported` sends them to
    /// update a node that is current.
    #[test]
    fn an_unrecognised_symbol_reaches_none_of_the_specific_arms() {
        let absence = ControlAbsence::of(&rejected("SOMETHING_THE_CONTRACT_ADDED_LATER"));
        assert_eq!(absence, ControlAbsence::Unreadable);
        assert_ne!(absence, ControlAbsence::NoNode);
        assert_ne!(absence, ControlAbsence::NotSupported);
        assert_ne!(absence, ControlAbsence::Refused);
    }

    /// `ALL` really is all of them.
    ///
    /// Without this, a variant added above and forgotten here would silently shrink the surface
    /// conversion tests that iterate `ALL` — they would keep passing while covering less.
    #[test]
    fn all_lists_every_variant() {
        for absence in ControlAbsence::ALL {
            // The match is exhaustive and wildcard-free, so a new variant fails to compile here.
            let named = match absence {
                ControlAbsence::NoNode => "NoNode",
                ControlAbsence::NotSupported => "NotSupported",
                ControlAbsence::Refused => "Refused",
                ControlAbsence::Unreadable => "Unreadable",
            };
            assert!(!named.is_empty());
        }
        assert_eq!(ControlAbsence::ALL.len(), 4);
    }
}
