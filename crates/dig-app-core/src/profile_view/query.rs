//! What a person typed, understood: a store id DIG can look up, or a DID it cannot yet.
//!
//! # Why a DID parses but does not resolve
//!
//! A profile is a DID singleton and the dig-store singleton launched from that DID's coin, and the
//! link runs one way: a store's anchor records which DID coin launched it, and nothing on chain
//! indexes the reverse. Turning a `did:chia:…` into its store therefore needs profile DISCOVERY
//! (dig_ecosystem#2392), which no layer of the ecosystem has yet — not dig-account, not dig-did, and
//! not the node's control plane.
//!
//! So a DID is RECOGNISED here and refused with the reason, rather than either being rejected as
//! gibberish — which would tell a person their DID is malformed when it is fine — or silently
//! searched for and reported as "no such profile", which would be a lie about the chain.

/// The `did:chia:` prefix every DIG DID string carries.
const DID_PREFIX: &str = "did:chia:";

/// How many hex characters a store launcher id is: 32 bytes.
pub const STORE_ID_HEX_LEN: usize = 64;

/// A profile lookup that could be attempted, as understood from what was typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileQuery {
    /// A dig-store singleton launcher id: lowercase hex, no `0x` prefix, ready to look up.
    Store(String),
    /// A `did:chia:` string, which names a profile DIG cannot yet resolve to its store.
    Did(String),
}

/// Why what was typed is not something to look up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryProblem {
    /// Nothing was typed. Not an error to shout about — it is the state the box opens in.
    Empty,
    /// It is hex of the wrong length to be a store id.
    ///
    /// Told apart from [`NotAnId`](Self::NotAnId) because it is nearly always a truncated paste,
    /// and "that is 63 characters and a store id is 64" is a fixable sentence where "that is not a
    /// store id" is not.
    WrongLength {
        /// How many hex characters were given, after any `0x` prefix.
        len: usize,
    },
    /// It is neither a store id nor a DID.
    NotAnId,
}

impl QueryProblem {
    /// What to tell a person, in words that name the remedy.
    pub fn sentence(&self) -> String {
        match self {
            Self::Empty => "Paste a store id to look up somebody's profile.".to_string(),
            Self::WrongLength { len } => format!(
                "A store id is {STORE_ID_HEX_LEN} characters of hex and this is {len}. It may have been cut short when it was copied."
            ),
            Self::NotAnId => {
                "That is neither a store id nor a did:chia: identifier. A store id is 64 characters of hex.".to_string()
            }
        }
    }
}

impl ProfileQuery {
    /// Understand `typed`, or say why it cannot be understood.
    ///
    /// Tolerant about the things a paste does to a value and strict about the value itself: leading
    /// and trailing space is dropped, a `0x` prefix is accepted, and case is normalised — because
    /// every one of those is the same id, and refusing them would be refusing a correct answer for
    /// how it arrived.
    ///
    /// # Errors
    ///
    /// A [`QueryProblem`] naming which of the three ways it failed, so the pane can say the useful
    /// sentence rather than a generic one.
    pub fn of(typed: &str) -> Result<Self, QueryProblem> {
        let trimmed = typed.trim();
        if trimmed.is_empty() {
            return Err(QueryProblem::Empty);
        }
        if trimmed.starts_with(DID_PREFIX) {
            return Ok(Self::Did(trimmed.to_string()));
        }

        let body = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        if !body.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(QueryProblem::NotAnId);
        }
        if body.len() != STORE_ID_HEX_LEN {
            return Err(QueryProblem::WrongLength { len: body.len() });
        }
        Ok(Self::Store(body.to_ascii_lowercase()))
    }

    /// The store id to look up, for a query that names one.
    pub fn store_id(&self) -> Option<&str> {
        match self {
            Self::Store(id) => Some(id),
            Self::Did(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store id as it is printed everywhere in DIG: 64 lowercase hex characters.
    const ID: &str = "371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0371a39b0";

    /// **A pasted id is understood however it was copied.**
    ///
    /// Every one of these is the SAME id — the same 32 bytes — and a surface that accepted one
    /// spelling and refused another would be refusing a correct answer for how it arrived. The
    /// spellings are the ones DIG itself prints: bare hex in a log, `0x`-prefixed on a card, and
    /// whatever a terminal selection puts around it.
    #[test]
    fn every_spelling_of_one_store_id_is_the_same_query() {
        for spelling in [
            ID.to_string(),
            format!("0x{ID}"),
            format!("  {ID}\n"),
            ID.to_ascii_uppercase(),
            format!("0X{}", ID.to_ascii_uppercase()),
        ] {
            assert_eq!(
                ProfileQuery::of(&spelling),
                Ok(ProfileQuery::Store(ID.to_string())),
                "the spelling {spelling:?} was not understood as the id it is"
            );
        }
    }

    /// **A truncated paste is told apart from gibberish.**
    ///
    /// The distinguishing fixture is hex that is one character short: it is the commonest real
    /// failure — a selection that missed the last character — and it is indistinguishable from
    /// gibberish to any check that only asks "is this a valid store id". The control beside it is a
    /// value of the RIGHT length that is not hex, which must not be reported as a length problem.
    #[test]
    fn a_short_paste_says_it_is_short_and_a_non_id_says_it_is_not_one() {
        let short = &ID[..ID.len() - 1];
        assert_eq!(
            ProfileQuery::of(short),
            Err(QueryProblem::WrongLength { len: 63 }),
            "a paste one character short was not reported as short"
        );

        let right_length_not_hex = "z".repeat(STORE_ID_HEX_LEN);
        assert_eq!(
            ProfileQuery::of(&right_length_not_hex),
            Err(QueryProblem::NotAnId),
            "a 64-character non-hex value was reported as a length problem, which points a person at the wrong fix"
        );
    }

    /// **A DID is recognised, and is not mistaken for a malformed store id.**
    ///
    /// The property that matters is which SENTENCE a person gets. A DID holder whose DID is fine
    /// must not be told their identifier is gibberish, so the fixture is a well-formed DID and the
    /// assertion is that it parses — the refusal to resolve it happens a layer up, with its own
    /// reason.
    #[test]
    fn a_did_parses_as_a_did_rather_than_as_a_broken_store_id() {
        let did = "did:chia:1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        assert_eq!(
            ProfileQuery::of(did),
            Ok(ProfileQuery::Did(did.to_string())),
            "a did:chia: string was not recognised as a DID"
        );
        assert_eq!(
            ProfileQuery::of(did).expect("a DID parses").store_id(),
            None,
            "a DID offered a store id to look up, which would resolve the wrong store"
        );
    }

    /// **An empty box is not an error.**
    #[test]
    fn an_empty_box_is_its_own_problem_and_not_a_malformed_id() {
        assert_eq!(ProfileQuery::of("   "), Err(QueryProblem::Empty));
        assert!(
            !QueryProblem::Empty
                .sentence()
                .to_lowercase()
                .contains("not"),
            "the empty box is told it is wrong, on a surface nobody has used yet"
        );
    }
}
