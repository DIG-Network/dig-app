//! The money seam behind `spend.request` (`SPEC.md` §5.6.8, **security-critical**).
//!
//! `spend.request` is the ONE loopback method that can move a user's money. It is a different power
//! from `sign.request`, which produces a typed `DIGNET-SIGN-v1` identity attestation that no
//! consensus rule will ever accept — so the two are separate methods under separate capabilities,
//! and neither implies the other.
//!
//! # Why this is a trait and not a call into `MoneyPath`
//!
//! [`MoneyPath::authorize_and_sign`](crate::account::money::MoneyPath::authorize_and_sign) is async,
//! and the [`FrameRouter`](super::FrameRouter) that routes every loopback frame is deliberately
//! synchronous — that is what makes its auth gate, its capability table and its error taxonomy
//! exhaustively unit-testable without a socket or a runtime. Making the router async to reach the
//! money path would have converted every one of those security-critical tests for no gain in
//! coverage.
//!
//! Blocking is not a new hazard on this path either. The router already blocks its thread on a human
//! for the whole of a native sign confirm, and it is served on its own dedicated thread
//! (`sign_service::serve_blocking`), so a spend ceremony that takes minutes blocks exactly what a
//! sign ceremony already blocks.
//!
//! So the router depends on this SEAM, in the same house style as
//! [`SessionSigner`](crate::session::SessionSigner) and
//! [`SignReauthGate`](super::SignReauthGate): a trait it can be given a fake of, whose production
//! implementation lives at the wiring layer where a `MoneyPath`, a publisher and a runtime all exist.
//!
//! # The default is fail-closed
//!
//! A router assembled without a money seam gets [`NoSpendAuthority`], which refuses every spend as
//! [`SpendRefusal::Unavailable`]. An app that has not wired its wallet therefore cannot be talked
//! into spending by a frame; it says it cannot, which is true.

use chia_protocol::CoinSpend;

/// What is known about a signed bundle's journey to a mempool — and what is deliberately NOT claimed.
///
/// There is no `Sent` and no `Confirmed` variant, on purpose. A push that a mempool accepted is an
/// ACCEPTANCE, never a payment: the money is settled when the chain says so and not before, and a
/// wire word like "sent" invites a caller to tell its user something the app cannot know
/// (`wallet/send.rs` states the same rule for the in-app Send control).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushDisposition {
    /// The caller asked for the signed bytes only (`broadcast: false`). Nothing was pushed and
    /// nothing will be — publishing is now the caller's act.
    NotBroadcast,
    /// A mempool accepted the bundle (or already held it). It may confirm; it is not money yet.
    Pending,
    /// The push left and nothing ruled on it. **The bundle may be in a mempool.** A caller MUST NOT
    /// rebuild and resend on this answer — the same rule that holds the in-app Send control closed on
    /// `SendError::PushUnanswered`, because a second bundle over fresh inputs can pay the recipient
    /// twice.
    Unknown,
}

impl PushDisposition {
    /// The stable wire word (`SPEC.md` §5.6.8). Exactly three, and none of them says "sent".
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::NotBroadcast => "not_broadcast",
            Self::Pending => "pending",
            Self::Unknown => "unknown",
        }
    }
}

/// A signed spend, ready to return over the loopback channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSpend {
    /// Base64 of the streamable signed [`SpendBundle`](chia_protocol::SpendBundle) — the same
    /// encoding the request's `payload_b64` carried unsigned, so a caller round-trips one shape.
    pub bundle_b64: String,
    /// The bundle's id, hex, for correlation. A name, never a receipt.
    pub bundle_id_hex: String,
    /// What is known about the push. See [`PushDisposition`].
    pub push: PushDisposition,
}

/// Why a spend produced no bundle. Every variant means **nothing was signed and nothing was sent**.
///
/// A push whose outcome is genuinely unknown is NOT here: it is a success carrying
/// [`PushDisposition::Unknown`], because the bundle exists and may be in a mempool, and reporting
/// that as a failure would invite exactly the rebuild-and-resend that pays a recipient twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendRefusal {
    /// The account is locked — no key, no signature.
    Locked,
    /// The custody gate refused the spend outright, the profile moved during the ceremony, custody is
    /// configured as a vault this app cannot honour, or signing itself failed. Structural: no
    /// ceremony and no retry of the same request can turn it into a signature.
    Refused(String),
    /// The human declined the confirm ceremony, or it timed out. The spend was permissible; consent
    /// was not given.
    Declined(Option<String>),
    /// No ceremony could be raised (a headless host, no window). Fail-closed — never a silent decline
    /// dressed as the user's choice.
    Unavailable(String),
}

/// The money path, as the frame router sees it: rule on these coin spends, obtain the human's
/// agreement, sign in-process, and — only if asked — publish.
///
/// # The custody boundary (§908) is the implementation's to keep
///
/// Signing happens inside the process, in dig-account's money signer under its `CustodyScope`. What
/// this trait returns is an already-signed bundle; what any implementation may hand a node is an
/// already-signed bundle. **The node is asked to sign nothing at any point**, and no implementation
/// of this trait may make it so.
pub trait SpendAuthority: Send + Sync {
    /// Authorize, sign, and optionally publish `coin_spends`.
    ///
    /// The op class is NOT a parameter. Anything reaching this seam arrived from outside the process,
    /// so the implementation MUST pass `SpendOpClass::Undeclared` — the class that can never
    /// auto-approve and always routes to the human. Letting a caller state the class would let an
    /// origin's own words decide whether a person is asked.
    fn authorize_and_sign(
        &self,
        coin_spends: Vec<CoinSpend>,
        broadcast: bool,
    ) -> Result<SignedSpend, SpendRefusal>;
}

/// The fail-closed default seam: refuses every spend because no wallet is wired.
///
/// Distinct from a decline, and distinct from a lock: nothing here could ever have signed, and the
/// message says so rather than inviting a caller to prompt for a password that would not help.
pub struct NoSpendAuthority;

impl SpendAuthority for NoSpendAuthority {
    fn authorize_and_sign(
        &self,
        _coin_spends: Vec<CoinSpend>,
        _broadcast: bool,
    ) -> Result<SignedSpend, SpendRefusal> {
        Err(SpendRefusal::Unavailable(
            "this app has no wallet wired to the spend seam".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_wire_words_are_exactly_the_spec_set_and_none_of_them_claims_a_send() {
        // Pinned from BOTH sides: the three permitted words are present in order, and the two
        // forbidden ones are unproducible. A test that only listed the three could not see a fourth.
        let all = [
            PushDisposition::NotBroadcast,
            PushDisposition::Pending,
            PushDisposition::Unknown,
        ];
        let words: Vec<_> = all.iter().map(|d| d.wire_name()).collect();
        assert_eq!(words, ["not_broadcast", "pending", "unknown"]);
        assert!(!words.contains(&"sent"), "`sent` claims a fact nobody has");
        assert!(
            !words.contains(&"confirmed"),
            "only the chain says confirmed"
        );
    }

    #[test]
    fn the_default_seam_refuses_every_spend_rather_than_answering_for_a_wallet_it_lacks() {
        let refusal = NoSpendAuthority
            .authorize_and_sign(vec![], true)
            .unwrap_err();
        assert!(matches!(refusal, SpendRefusal::Unavailable(_)));
    }
}
