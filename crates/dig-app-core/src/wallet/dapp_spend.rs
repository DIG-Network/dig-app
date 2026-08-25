//! The production money seam behind `spend.request` (`SPEC.md` §5.6.8, **security-critical**).
//!
//! [`DappSpendAuthority`] is the one implementation of
//! [`SpendAuthority`](crate::loopback::SpendAuthority) that can actually move money: it stages the
//! honest confirm narrative, drives [`MoneyPath::authorize_and_sign`], and — only when the caller
//! asked — hands the SIGNED bytes to the node.
//!
//! Nothing here is new custody machinery. It is the same four steps `wallet::send` performs for the
//! user's own Send control, with two differences that both tighten it:
//!
//! - the op class is [`SpendOpClass::Undeclared`], because the spend was built OUTSIDE this process
//!   and no caller can truthfully declare what it is for. That class can never auto-approve, so every
//!   dapp spend reaches a human however generously `AutoSendPolicy` is configured;
//! - the confirm body carries a narrative that names whether DIG will BROADCAST the bundle or hand it
//!   back, so the person is agreeing to the act that will actually happen.
//!
//! # The custody boundary (§908)
//!
//! Signing happens in-process, in dig-account's money signer under its `CustodyScope`. What crosses
//! to the node is an already-signed [`SpendBundle`]; the node signs nothing and is never asked to.
//!
//! # Why this blocks
//!
//! [`SpendAuthority`] is synchronous because the loopback frame router is (see
//! `loopback::spend`). The router is served on its own dedicated thread, and it already blocks that
//! thread for the whole of a native sign confirm, so blocking it on a spend ceremony is the existing
//! behaviour of the existing thread rather than a new hazard.

use std::sync::Arc;

use chia_protocol::{CoinSpend, SpendBundle};
use chia_traits::Streamable as _;
use dig_account::mint::PushOutcome;
use dig_account::{AuthProvider, SpendOpClass};

use crate::account::money::{MoneyPath, MoneyPathError};
use crate::account::narrative::{NarrativeSlot, TradeNarrative};
use crate::chain::DetailedSpendPublisher;
use crate::loopback::{PushDisposition, SignedSpend, SpendAuthority, SpendRefusal};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

/// The live money seam: a [`MoneyPath`], the node publisher, and the narrative slot the confirm
/// ceremony reads.
pub struct DappSpendAuthority<P: AuthProvider, Pub: DetailedSpendPublisher> {
    money: Arc<MoneyPath<P>>,
    publisher: Arc<Pub>,
    /// The slot the confirm ceremony reads its headline from. Shared with the ceremony, so what is
    /// staged here is what the person is shown.
    narrative: NarrativeSlot,
    /// The runtime the async money path is driven on.
    runtime: tokio::runtime::Handle,
}

impl<P: AuthProvider, Pub: DetailedSpendPublisher> DappSpendAuthority<P, Pub> {
    /// Assemble the seam over a live money path, the node publisher, and the ceremony's narrative
    /// slot.
    pub fn new(
        money: Arc<MoneyPath<P>>,
        publisher: Arc<Pub>,
        narrative: NarrativeSlot,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            money,
            publisher,
            narrative,
            runtime,
        }
    }
}

/// The confirm narrative for a spend an outside app asked for.
///
/// Its whole job is to make the screen honest about the ACT, which the re-derived figures cannot say
/// on their own: they show what a signature would authorize, not whether this app is about to
/// broadcast it. A person approving "sign this" and a person approving "sign and send this" are
/// agreeing to different things, and only one of them is happening.
///
/// The recipients, amounts and fee still follow underneath, unedited and re-derived by `dig-account`
/// from the coin spends — this is additional evidence, never a replacement for them.
pub(crate) fn dapp_spend_narrative(broadcast: bool) -> TradeNarrative {
    if broadcast {
        TradeNarrative {
            headline: "Approve and SEND this payment?".to_string(),
            you_give: vec![
                "DIG will sign this payment and broadcast it to the Chia network.".to_string(),
            ],
            you_receive: Vec::new(),
            caution: Some(
                "A broadcast payment cannot be recalled. Check the recipient and the amount below."
                    .to_string(),
            ),
        }
    } else {
        TradeNarrative {
            headline: "Sign this payment?".to_string(),
            you_give: vec![
                "DIG will sign this payment and hand the signed transaction back to the app that \
                 asked. DIG will NOT broadcast it."
                    .to_string(),
            ],
            you_receive: Vec::new(),
            caution: Some(
                "The app that asked can broadcast it at any time after you approve. Approving is \
                 the last point at which you can stop this payment."
                    .to_string(),
            ),
        }
    }
}

impl<P: AuthProvider, Pub: DetailedSpendPublisher + Send + Sync> SpendAuthority
    for DappSpendAuthority<P, Pub>
where
    P: Send + Sync,
{
    fn authorize_and_sign(
        &self,
        coin_spends: Vec<CoinSpend>,
        broadcast: bool,
    ) -> Result<SignedSpend, SpendRefusal> {
        // Staged for the LIFE of the ceremony and cleared when this guard drops, so a later
        // confirmation never inherits this one's words.
        let _staged = self.narrative.set(dapp_spend_narrative(broadcast));

        // `Undeclared` is not a parameter and never will be: the spend was built outside this
        // process, so nobody here can truthfully say what it is for, and that class can never
        // auto-approve.
        let bundle = self
            .runtime
            .block_on(
                self.money
                    .authorize_and_sign(coin_spends, SpendOpClass::Undeclared),
            )
            .map_err(refusal_of)?;

        let push = if broadcast {
            self.publish(&bundle)?
        } else {
            // The publisher is not consulted AT ALL. Not called and told to skip — not called.
            PushDisposition::NotBroadcast
        };

        let bytes = bundle
            .to_bytes()
            .map_err(|e| SpendRefusal::Refused(format!("the signed bundle would not encode: {e}")))?;
        Ok(SignedSpend {
            bundle_b64: BASE64.encode(bytes),
            bundle_id_hex: hex::encode(bundle.name()),
            push,
        })
    }
}

impl<P: AuthProvider, Pub: DetailedSpendPublisher> DappSpendAuthority<P, Pub> {
    /// Push a SIGNED bundle and say only what is known about where it got to.
    fn publish(&self, bundle: &SpendBundle) -> Result<PushDisposition, SpendRefusal> {
        match self.publisher.push_detailed(bundle) {
            Ok(PushOutcome::Accepted | PushOutcome::AlreadyInMempool) => Ok(PushDisposition::Pending),
            // A mempool RULED on it and said no. The bundle is dead, so returning it under any of the
            // three push words would name a journey it is not on; the reason is what the caller can
            // act on.
            Ok(PushOutcome::Rejected { reason }) => Err(SpendRefusal::Refused(format!(
                "a mempool rejected the signed bundle: {reason}"
            ))),
            // Nothing ruled on it and it MAY be in a mempool. Reported as a SUCCESS carrying
            // `Unknown`, because a failure here invites the rebuild-and-resend that pays the
            // recipient twice — the same rule that holds the in-app Send control closed.
            Err(failure) if failure.may_have_reached_a_mempool() => Ok(PushDisposition::Unknown),
            // It provably never left, so no mempool holds it and the signed bundle is intact. The
            // caller asked for a broadcast and gets `not_broadcast`, which against its own
            // `broadcast: true` reads unambiguously as "we tried, and nothing received it".
            Err(_) => Ok(PushDisposition::NotBroadcast),
        }
    }
}

/// Classify a money-path failure for the wire.
fn refusal_of(error: MoneyPathError) -> SpendRefusal {
    match error {
        MoneyPathError::Locked => SpendRefusal::Locked,
        MoneyPathError::Declined(why) => SpendRefusal::Declined(why),
        // Structural: the gate said no, the profile moved under the consent, custody is a vault this
        // app cannot honour, the spend would not re-derive, or signing failed. Repeating the
        // identical request cannot change any of them.
        other => SpendRefusal::Refused(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_broadcast_narrative_says_send_and_the_sign_only_narrative_says_it_will_not() {
        // The property: the person is told which of the two acts they are approving. The fixture
        // varies ONE thing — the flag — and asserts the two bodies make OPPOSITE claims, which a
        // single shared sentence could not satisfy.
        let sending = dapp_spend_narrative(true);
        let signing = dapp_spend_narrative(false);

        assert_ne!(
            sending.headline, signing.headline,
            "one screen approving two different acts must not ask the same question"
        );
        let sending_body = sending.you_give.join(" ");
        let signing_body = signing.you_give.join(" ");
        assert!(
            sending_body.contains("broadcast it"),
            "the broadcasting case must SAY it broadcasts: {sending_body}"
        );
        assert!(
            signing_body.contains("NOT broadcast"),
            "the sign-only case must say it does not: {signing_body}"
        );
        assert!(
            signing.caution.unwrap().contains("can broadcast it"),
            "and it must not leave the person believing the payment is therefore stopped — the app \
             it hands the bytes to can send them"
        );
    }
}
