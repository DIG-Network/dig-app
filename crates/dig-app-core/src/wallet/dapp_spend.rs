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

/// Yields the money path in force RIGHT NOW, or `None` when the account is locked.
///
/// See [`DappSpendAuthority`] for why this is a factory and not a value.
pub type MoneyPathSource<P> = Arc<dyn Fn() -> Option<Arc<MoneyPath<P>>> + Send + Sync>;

/// Yields the publisher for the node in force RIGHT NOW, or `None` when no node endpoint is known.
///
/// A factory for the same reason [`MoneyPathSource`] is one: the node endpoint is resolved from a
/// live ladder that can change while the app runs, and a publisher captured at boot would go on
/// pushing at an address that may no longer be serving.
pub type PublisherSource<Pub> = Arc<dyn Fn() -> Option<Pub> + Send + Sync>;

/// The live money seam: a source of money paths, the node publisher, and the narrative slot the
/// confirm ceremony reads.
///
/// # Why the money path is a FACTORY and not a held value
///
/// A [`MoneyPath`] decodes the profile's hot-wallet receive address at construction — the address the
/// custody gate compares every payee against — and it can only be built while the account is
/// unlocked. The router that owns this seam is moved onto a serving thread for the life of the
/// process, so one path built at boot would go on gating against whichever profile was active THEN,
/// however many times the user switched or locked since. That is the staleness [`Live`](crate::live)
/// exists to prevent, on the one surface where being stale means comparing a payment against a
/// stranger's address.
///
/// So the path is read at the moment of use. A locked account yields `None` here and the spend fails
/// [`SpendRefusal::Locked`] — never a spend gated by a profile the user has left.
pub struct DappSpendAuthority<P: AuthProvider, Pub: DetailedSpendPublisher> {
    money: MoneyPathSource<P>,
    publisher: PublisherSource<Pub>,
    /// The slot the confirm ceremony reads its headline from. Shared with the ceremony, so what is
    /// staged here is what the person is shown.
    narrative: NarrativeSlot,
    /// The runtime the async money path is driven on.
    runtime: tokio::runtime::Handle,
}

impl<P: AuthProvider, Pub: DetailedSpendPublisher> DappSpendAuthority<P, Pub> {
    /// Assemble the seam over a live source of money paths, the node publisher, and the ceremony's
    /// narrative slot.
    pub fn new(
        money: MoneyPathSource<P>,
        publisher: PublisherSource<Pub>,
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


/// The node endpoint a dapp-spend broadcast pushes through, once something has installed one.
///
/// A `Mutex` rather than a `OnceLock`, mirroring `profile_melt::APP_SEAMS`: the engine reconnects on
/// a new endpoint while the app runs, and a value captured at boot would go on pushing at an address
/// that may no longer be serving. Reading before anything installs answers `None`, which the push
/// path reports as `not_broadcast` — nothing was attempted, so the caller may try again.
static NODE_ENDPOINT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Publish the endpoint the engine is currently connected to. Replaces whatever was installed before.
pub fn install_node_endpoint(endpoint: &str) {
    if let Ok(mut held) = NODE_ENDPOINT.lock() {
        if held.as_deref() != Some(endpoint) {
            tracing::info!(endpoint, "dapp-spend broadcast endpoint wired");
            *held = Some(endpoint.to_string());
        }
    }
}

/// The endpoint a dapp-spend broadcast would push through right now, if any.
///
/// A poisoned lock answers `None`, which is the fail-closed direction: no push is attempted, and the
/// caller is told so honestly rather than being left to believe money left.
pub fn node_endpoint() -> Option<String> {
    NODE_ENDPOINT.lock().ok().and_then(|held| held.clone())
}

/// The production publisher source: a fresh publisher at whatever endpoint is installed right now.
pub fn live_publisher_source() -> PublisherSource<crate::chain::ControlSpendPublisher> {
    Arc::new(|| node_endpoint().map(crate::chain::ControlSpendPublisher::new))
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
        // Read the money path HERE, not at construction: a lock or a profile switch that landed since
        // boot is observed now rather than gated against a profile the user has left.
        let Some(money) = (self.money)() else {
            return Err(SpendRefusal::Locked);
        };

        let bundle = self
            .runtime
            .block_on(money.authorize_and_sign(coin_spends, SpendOpClass::Undeclared))
            .map_err(refusal_of)?;

        // ONE call, unconditional, passing the flag straight through. The decision to publish lives
        // entirely inside `push_if_asked`, so there is exactly one place in this crate that consults
        // `broadcast` and it is the place the tests below drive directly.
        let push = push_if_asked((self.publisher)().as_ref(), &bundle, broadcast)?;

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

/// Publish a SIGNED bundle if the caller asked, and say only what is known about where it got to.
///
/// # `broadcast: false` means the publisher is NOT CALLED
///
/// Not called and told to skip, not called and its answer discarded — not called. That is the whole
/// guarantee, and it is why this function takes the flag rather than being invoked behind an `if` at
/// its call site: a second branch elsewhere could drift from this one, and a caller that pushed and
/// then reported `not_broadcast` would satisfy any assertion made on the returned word alone.
fn push_if_asked(
    publisher: Option<&impl DetailedSpendPublisher>,
    bundle: &SpendBundle,
    broadcast: bool,
) -> Result<PushDisposition, SpendRefusal> {
    if !broadcast {
        return Ok(PushDisposition::NotBroadcast);
    }
    // No node endpoint is known, so nothing was even attempted. `not_broadcast` is exactly true, and
    // the caller MAY try again — which `unknown` would wrongly forbid.
    let Some(publisher) = publisher else {
        return Ok(PushDisposition::NotBroadcast);
    };
    match publisher.push_detailed(bundle) {
        Ok(PushOutcome::Accepted | PushOutcome::AlreadyInMempool) => Ok(PushDisposition::Pending),
        // A mempool RULED on it and said no. The bundle is dead, so returning it under any of the
        // three push words would name a journey it is not on; the reason is what the caller can act
        // on.
        Ok(PushOutcome::Rejected { reason }) => Err(SpendRefusal::Refused(format!(
            "a mempool rejected the signed bundle: {reason}"
        ))),
        // Nothing ruled on it and it MAY be in a mempool. Reported as a SUCCESS carrying `Unknown`,
        // because a failure here invites the rebuild-and-resend that pays the recipient twice — the
        // same rule that holds the in-app Send control closed.
        Err(failure) if failure.may_have_reached_a_mempool() => Ok(PushDisposition::Unknown),
        // It provably never left, so no mempool holds it. The caller asked for a broadcast and gets
        // `not_broadcast`, which against its own `broadcast: true` reads unambiguously as "we tried,
        // and nothing received it" — and correctly permits it to try again.
        Err(_) => Ok(PushDisposition::NotBroadcast),
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

    use crate::chain::PublishFailure;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A publisher that COUNTS pushes and can be told what to answer.
    ///
    /// The count is the assertion, never the returned word: an implementation that pushed and then
    /// reported `not_broadcast` would satisfy any test written against the answer alone, and that is
    /// precisely the implementation this must be able to fail.
    struct CountingPublisher {
        pushes: AtomicUsize,
        answer: fn() -> Result<PushOutcome, PublishFailure>,
    }

    impl CountingPublisher {
        fn accepting() -> Self {
            Self {
                pushes: AtomicUsize::new(0),
                answer: || Ok(PushOutcome::Accepted),
            }
        }
        fn pushes(&self) -> usize {
            self.pushes.load(Ordering::SeqCst)
        }
    }

    impl DetailedSpendPublisher for CountingPublisher {
        fn push_detailed(&self, _bundle: &SpendBundle) -> Result<PushOutcome, PublishFailure> {
            self.pushes.fetch_add(1, Ordering::SeqCst);
            (self.answer)()
        }
    }

    fn empty_bundle() -> SpendBundle {
        SpendBundle::new(Vec::new(), chia_bls::Signature::default())
    }

    /// **`broadcast: false` does not reach the publisher — it is not called at all.**
    ///
    /// Both sides are pinned. The false case asserts ZERO pushes, which no
    /// push-then-discard-the-answer implementation can satisfy; the true case asserts exactly ONE,
    /// which rules out a version that simply never publishes and would otherwise pass the first
    /// assertion for the wrong reason.
    #[test]
    fn a_spend_that_was_not_asked_to_broadcast_never_touches_the_publisher() {
        let publisher = CountingPublisher::accepting();
        let disposition = push_if_asked(Some(&publisher), &empty_bundle(), false).unwrap();
        assert_eq!(
            0,
            publisher.pushes(),
            "the publisher must not be CALLED — reporting `not_broadcast` after pushing would be a              surface lying about whether money left"
        );
        assert_eq!(PushDisposition::NotBroadcast, disposition);

        let publisher = CountingPublisher::accepting();
        let disposition = push_if_asked(Some(&publisher), &empty_bundle(), true).unwrap();
        assert_eq!(
            1,
            publisher.pushes(),
            "control: asking for a broadcast must actually push, or the assertion above passes for              an implementation that never publishes at all"
        );
        assert_eq!(PushDisposition::Pending, disposition);
    }

    /// **An unanswered push is a SUCCESS carrying `unknown`, never a failure.**
    ///
    /// The bundle may be in a mempool. Reporting a failure would invite the caller to rebuild and
    /// resend, and a rebuild over fresh inputs can pay the recipient twice — the exact rule that
    /// holds the in-app Send control closed on `PushUnanswered`.
    #[test]
    fn a_push_nobody_answered_is_unknown_and_not_an_error() {
        let publisher = CountingPublisher {
            pushes: AtomicUsize::new(0),
            // `Unreachable` is one of the two failures `may_have_reached_a_mempool` calls TRUE, so
            // this fixture exercises the branch under test rather than the fail-fast one beside it.
            answer: || {
                Err(PublishFailure::Unreachable {
                    detail: "nothing answered".to_string(),
                })
            },
        };
        let outcome = push_if_asked(Some(&publisher), &empty_bundle(), true);
        assert_eq!(
            Ok(PushDisposition::Unknown),
            outcome,
            "an unruled push must not be reported as a failure the caller may retry: {outcome:?}"
        );
    }

    /// **A mempool that RULED against the bundle is a refusal, not one of the three push words.**
    ///
    /// The bundle is dead, so `not_broadcast`, `pending` and `unknown` would each name a journey it
    /// is not on. The mempool's own reason is what the caller can act on.
    #[test]
    fn a_bundle_a_mempool_rejected_is_refused_rather_than_given_a_push_word() {
        let publisher = CountingPublisher {
            pushes: AtomicUsize::new(0),
            answer: || {
                Ok(PushOutcome::Rejected {
                    reason: "DOUBLE_SPEND".to_string(),
                })
            },
        };
        let outcome = push_if_asked(Some(&publisher), &empty_bundle(), true);
        match outcome {
            Err(SpendRefusal::Refused(why)) => assert!(
                why.contains("DOUBLE_SPEND"),
                "the mempool reason must survive to the caller: {why}"
            ),
            other => panic!("a rejected bundle must not come back under a push word: {other:?}"),
        }
    }

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

    /// **With no node endpoint known, a broadcast-requested spend reports `not_broadcast`.**
    ///
    /// Nothing was attempted, so no mempool can hold it and the caller MAY retry — which `unknown`
    /// would wrongly forbid, and which is the whole reason those two words are not interchangeable.
    #[test]
    fn a_broadcast_with_no_node_reports_not_broadcast_rather_than_unknown() {
        let absent: Option<&CountingPublisher> = None;
        assert_eq!(
            Ok(PushDisposition::NotBroadcast),
            push_if_asked(absent, &empty_bundle(), true),
            "an unattempted push must not be reported as one that may be in a mempool"
        );
    }

}
