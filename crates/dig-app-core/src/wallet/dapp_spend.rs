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
///
/// # Why it takes the narrative slot
///
/// The ceremony inside the money path renders whatever is staged in the slot it holds, so the slot
/// the seam stages into MUST be the slot that ceremony reads. Passing it per call lets the seam mint
/// a FRESH slot for every spend, which is what makes two overlapping ceremonies structurally unable
/// to show each other's words — rather than merely unlikely to (dig_ecosystem#1552, re-gate).
pub type MoneyPathSource<P> =
    Arc<dyn Fn(&NarrativeSlot) -> Option<Arc<MoneyPath<P>>> + Send + Sync>;

/// Yields the publisher for the node in force RIGHT NOW, or `None` when no node endpoint is known.
///
/// A factory for the same reason [`MoneyPathSource`] is one: the node endpoint is resolved from a
/// live ladder that can change while the app runs, and a publisher captured at boot would go on
/// pushing at an address that may no longer be serving.
pub type PublisherSource<Pub> = Arc<dyn Fn() -> Option<Pub> + Send + Sync>;

/// Yields the runtime handle the async money path is driven on.
///
/// A factory so the runtime can be created on the FIRST SPEND rather than at boot. Starting one at
/// boot would put a thread pool into a GUI process that may never spend at all, and boot is the one
/// place in this app where an added side effect has already produced a user-visible regression that
/// no test could catch.
pub type RuntimeSource = Arc<dyn Fn() -> tokio::runtime::Handle + Send + Sync>;

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
/// # Why there is no narrative field
///
/// The confirm narrative is minted PER SPEND, in `authorize_and_sign`, and handed to the money source
/// so the ceremony it builds reads that same slot. A slot held here would be shared by every spend
/// this seam ever serves, and two overlapping ceremonies would then overwrite each other's words —
/// one person reading request A's sentence while approving request B's payment.
///
/// That was previously argued to be unreachable because the loopback runs on a current-thread runtime
/// and this method is synchronous. Both remain true, but the argument was incomplete in the direction
/// that matters: `spawn_blocking` and `block_in_place` keep BOTH of those conditions while freeing the
/// thread, so the next person to fix a blocking bridge would have armed the race without touching
/// anything that looked related. A per-spend slot removes the question instead of answering it.
pub struct DappSpendAuthority<P: AuthProvider, Pub: DetailedSpendPublisher> {
    money: MoneyPathSource<P>,
    publisher: PublisherSource<Pub>,
    /// The runtime the async money path is driven on, created on first use.
    runtime: RuntimeSource,
}

impl<P: AuthProvider, Pub: DetailedSpendPublisher> DappSpendAuthority<P, Pub> {
    /// Assemble the seam over a live source of money paths and the node publisher.
    pub fn new(
        money: MoneyPathSource<P>,
        publisher: PublisherSource<Pub>,
        runtime: RuntimeSource,
    ) -> Self {
        Self {
            money,
            publisher,
            runtime,
        }
    }
}

/// Drive the async money path to completion from a SYNCHRONOUS caller that may itself be inside a
/// tokio task, and hand back the result.
///
/// # Why `Handle::block_on` cannot be used here, measured
///
/// This seam is called synchronously from a frame handler that the loopback server runs INSIDE an
/// async task (`sign_service::serve_blocking` → `LoopbackServer::serve` → a spawned per-connection
/// task). `Handle::block_on` detects that context and panics:
///
/// ```text
/// Cannot start a runtime from within a runtime. This happens because a function (like `block_on`)
/// attempted to block the current thread while the thread is being used to drive asynchronous tasks.
/// ```
///
/// So the production path panicked on its FIRST use — a defect no unit test saw, because every test
/// called the seam from an ordinary thread where `block_on` is perfectly legal. It was found by
/// probing the real nesting, and the test beside this function reproduces that nesting rather than a
/// convenient one.
///
/// # Why not `spawn_blocking` or `block_in_place`
///
/// Both would also work, and both would FREE the serving thread — which is precisely what makes a
/// second `spend.request` dispatchable while the first ceremony is still on screen. This does not: the
/// work is spawned onto a separate runtime and the calling thread parks on a channel receive, which
/// blocks without starting a runtime. The serving thread stays occupied exactly as before, so nothing
/// about the server's concurrency changes as a side effect of fixing a panic.
///
/// That is belt AND braces: the narrative slot is per-spend now, so an overlapping ceremony would be
/// harmless anyway. Neither mechanism is load-bearing alone.
///
/// # Errors
///
/// Propagates the money path's own [`MoneyPathError`]. A sender dropped without a value means the
/// spawned task was cancelled or panicked, which is reported as a refusal rather than a silent
/// success — nothing was signed in that case.
fn sign_off_thread<P>(
    runtime: tokio::runtime::Handle,
    money: Arc<MoneyPath<P>>,
    coin_spends: Vec<CoinSpend>,
) -> Result<SpendBundle, MoneyPathError>
where
    P: AuthProvider + Send + Sync + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    runtime.spawn(async move {
        let outcome = money
            .authorize_and_sign(coin_spends, SpendOpClass::Undeclared)
            .await;
        // A closed receiver means the caller is gone; the send failing is not itself an error.
        let _ = tx.send(outcome);
    });
    rx.recv().unwrap_or_else(|_| {
        Err(MoneyPathError::Unauthorized(
            "the signing task ended without answering".to_string(),
        ))
    })
}

/// The node endpoint a dapp-spend broadcast pushes through, once something has installed one.
///
/// A `Mutex` rather than a `OnceLock`, mirroring `profile_melt::APP_SEAMS`: the engine reconnects on
/// a new endpoint while the app runs, and a value captured at boot would go on pushing at an address
/// that may no longer be serving. Reading before anything installs answers `None`, which the push
/// path reports as `not_broadcast` — nothing was attempted, so the caller may try again.
///
/// This tracks the engine's CURRENT connection and is therefore written in BOTH directions — see
/// [`clear_node_endpoint`]. A one-way writer would make it a latch that outlives its own fact.
static NODE_ENDPOINT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Publish the endpoint the engine is currently connected to. Replaces whatever was installed before.
///
/// **Must be paired with [`clear_node_endpoint`] on the same cadence.** A writer that only ever
/// assigns `Some` turns this into a write-only latch, and a latch outlives the fact it recorded: the
/// endpoint would go on reading as installed long after the node it names stopped answering. That is
/// not a theoretical decay — dig-app is long-lived and dig-node restarts on the beacon's nightly
/// update, so "connected once, gone now" is the ordinary case rather than an exotic one.
pub fn install_node_endpoint(endpoint: &str) {
    if let Ok(mut held) = NODE_ENDPOINT.lock() {
        if held.as_deref() != Some(endpoint) {
            tracing::info!(endpoint, "dapp-spend broadcast endpoint wired");
            *held = Some(endpoint.to_string());
        }
    }
}

/// Retract the endpoint, because the engine is no longer connected to one.
///
/// # Why this exists, and why its absence was a money-lie
///
/// `publisher.is_some()` is what authorizes the confirm window to say *"DIG will broadcast it — a
/// broadcast payment cannot be recalled."* Without a clear path that predicate answers **"a string
/// was installed once"**, never **"a node is reachable"**: [`ControlSpendPublisher::new`] performs no
/// I/O, so it succeeds against a dead address exactly as it does against a live one.
///
/// The consequence was measured on this crate (dig_ecosystem#1552, re-gate): after the node goes
/// away mid-session, a `broadcast: true` spend still showed the irrevocable-send wording, pushed
/// nothing, and returned the signed bundle to the dapp — which is then free to broadcast it whenever
/// it likes, while the person believes the payment already left. `PushDisposition` reaches only the
/// JSON-RPC wire, so nothing on any screen corrects them.
///
/// Clearing it also stops this module silently overriding a contract one layer down:
/// `TrayStatus::engine.endpoint()` returns `None` while disconnected precisely so a caller cannot
/// "aim a read — or a push — at a machine this state already knows is unreachable."
pub fn clear_node_endpoint() {
    if let Ok(mut held) = NODE_ENDPOINT.lock() {
        if held.is_some() {
            tracing::info!("dapp-spend broadcast endpoint retracted: no node is connected");
            *held = None;
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
    // `'static` because the money path is moved onto the signing runtime — see `sign_off_thread`.
    P: Send + Sync + 'static,
{
    fn authorize_and_sign(
        &self,
        coin_spends: Vec<CoinSpend>,
        broadcast: bool,
    ) -> Result<SignedSpend, SpendRefusal> {
        // The publisher is resolved BEFORE the window is written, because the window has to describe
        // what will ACTUALLY happen (dig_ecosystem#1552, gate finding). Staging from the caller's
        // `broadcast` flag alone told a person "DIG will broadcast it, and a broadcast payment cannot
        // be recalled" and then, with no node reachable, signed and broadcast nothing — handing the
        // bundle to the dapp while the person believed the payment was irrevocably gone. Whether it
        // ever reached a mempool became the dapp's choice alone. That is a surface lying about
        // whether a privileged action took effect, inside the ceremony that IS the security control
        // for this path.
        //
        // One resolution, used for BOTH the sentence and the push, so the two cannot disagree.
        let publisher = (self.publisher)();
        let will_broadcast = broadcast && publisher.is_some();

        // A FRESH slot for THIS spend, staged for the life of the ceremony and cleared when the guard
        // drops. Per-spend rather than per-seam so two overlapping ceremonies cannot show each other's
        // words — see the type's docs for why the previous "unreachable" argument was not safe to keep
        // relying on.
        let narrative = NarrativeSlot::default();
        let _staged = narrative.set(dapp_spend_narrative(will_broadcast));

        // `Undeclared` is not a parameter and never will be: the spend was built outside this
        // process, so nobody here can truthfully say what it is for, and that class can never
        // auto-approve.
        // Read the money path HERE, not at construction: a lock or a profile switch that landed since
        // boot is observed now rather than gated against a profile the user has left.
        let Some(money) = (self.money)(&narrative) else {
            return Err(SpendRefusal::Locked);
        };

        let bundle = sign_off_thread((self.runtime)(), money, coin_spends).map_err(refusal_of)?;

        // Encode BEFORE pushing. `SPEND_REFUSED` promises that nothing was signed and nothing was
        // sent; an encode failure AFTER a successful push would break that promise on the one branch
        // where money had already moved. Doing the fallible, local step first makes the promise
        // structurally true rather than merely unreached (gate finding N2).
        let bytes = bundle.to_bytes().map_err(|e| {
            SpendRefusal::Refused(format!("the signed bundle would not encode: {e}"))
        })?;

        // ONE call, unconditional, passing the SAME resolution the window was written from. The
        // decision to publish lives entirely inside `push_if_asked`, so there is exactly one place in
        // this crate that consults it, and it is the place the tests below drive directly.
        let push = push_if_asked(publisher.as_ref(), &bundle, will_broadcast)?;
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
    ///
    /// # This test once described the ONLY reachable path as an edge case
    ///
    /// `install_node_endpoint` had no callers, so `NODE_ENDPOINT` was permanently `None` and this was
    /// what happened on EVERY broadcast — while the doc above called it the exceptional case. **A
    /// test that describes the only reachable path as exceptional is how a dead path reads as
    /// covered**, and it is why the far worse defect beside it (the window promising a broadcast that
    /// could never occur) went unnoticed by a green suite.
    ///
    /// It is genuinely exceptional now: the shell republishes the endpoint every frame, so this is
    /// the node-is-down case. The companion
    /// [`the_window_claims_a_broadcast_only_when_a_publisher_exists`] pins what the PERSON is told on
    /// this branch, which is the half that was never asserted.
    #[test]
    fn a_broadcast_with_no_node_reports_not_broadcast_rather_than_unknown() {
        let absent: Option<&CountingPublisher> = None;
        assert_eq!(
            Ok(PushDisposition::NotBroadcast),
            push_if_asked(absent, &empty_bundle(), true),
            "an unattempted push must not be reported as one that may be in a mempool"
        );
    }

    /// **The confirm window promises a broadcast only when a broadcast can actually happen.**
    ///
    /// # The defect this pins, and why nothing else caught it
    ///
    /// The narrative was staged from the caller's `broadcast` flag, while the push consulted the
    /// publisher. With no node endpoint installed those two disagreed silently: the person read
    /// *"DIG will sign this payment and broadcast it… a broadcast payment cannot be recalled"*, DIG
    /// signed, broadcast nothing, and handed the signed bundle to the dapp. Whether the payment ever
    /// reached a mempool became the dapp's choice alone, while the person believed it was already
    /// gone and irrevocable.
    ///
    /// # Why the fixture varies ONLY the publisher
    ///
    /// `broadcast` is held at `true` in BOTH arms. That is the whole point: the nearest wrong
    /// implementation reads the flag, so a fixture that also varied the flag would see the two
    /// sentences differ and pass while the bug was fully present. Varying one actor and keeping a
    /// truthful control is what makes this load-bearing.
    ///
    /// The assertion is on the STAGED NARRATIVE — what the person is shown — and not on the returned
    /// `push` word, which was already correct throughout and is exactly why the lie was invisible.
    #[test]
    fn the_window_claims_a_broadcast_only_when_a_publisher_exists() {
        // One spend per arm through a scripted publisher. See `narrative_staged_by` for how the
        // sentence is captured.
        let narrative_shown = |publisher_exists: bool| {
            let publisher: PublisherSource<CountingPublisher> = if publisher_exists {
                Arc::new(|| Some(CountingPublisher::accepting()))
            } else {
                Arc::new(|| None)
            };
            // `broadcast: true` in BOTH arms. Only the publisher differs.
            narrative_staged_by(publisher)
        };

        let with_a_node = narrative_shown(true);
        assert!(
            with_a_node.headline.contains("SEND"),
            "control: with a publisher the window must say the payment will be sent, or the              assertion below passes for an implementation that never promises a broadcast at all:              {}",
            with_a_node.headline
        );
        assert!(
            with_a_node
                .caution
                .as_deref()
                .is_some_and(|c| c.contains("cannot be recalled")),
            "control: and it must carry the irrevocability caution: {:?}",
            with_a_node.caution
        );

        let without_a_node = narrative_shown(false);
        assert!(
            !without_a_node.headline.contains("SEND"),
            "with no publisher DIG cannot broadcast, so the window must not say it will: {}",
            without_a_node.headline
        );
        assert!(
            !without_a_node
                .caution
                .as_deref()
                .is_some_and(|c| c.contains("cannot be recalled")),
            "and it must not warn about an irrevocability it is not about to create -- the bundle              goes back to the dapp, and whether it is ever sent is not settled here: {:?}",
            without_a_node.caution
        );
    }

    /// Run one `broadcast: true` spend through `publisher` and return the narrative it staged.
    ///
    /// The capture happens inside the money source, which the seam reads AFTER staging and BEFORE
    /// signing, so it observes exactly the sentence the ceremony would have shown. It then returns
    /// `None`, so the spend refuses `LOCKED` without needing a real `MoneyPath` — the refusal is
    /// irrelevant here; the sentence is the subject.
    fn narrative_staged_by<Pub: DetailedSpendPublisher + Send + Sync + 'static>(
        publisher: PublisherSource<Pub>,
    ) -> TradeNarrative {
        let seen = Arc::new(std::sync::Mutex::new(None));

        let captured = Arc::clone(&seen);
        // The slot now ARRIVES per spend, so the capture reads the one this very call staged into --
        // which is exactly the property being relied on.
        let money: MoneyPathSource<
            crate::account::auth::HarnessAuthProvider<crate::account::ceremony::PromptedCeremony>,
        > = Arc::new(move |narrative: &NarrativeSlot| {
            *captured.lock().unwrap() = narrative.get();
            None
        });

        let seam = DappSpendAuthority::new(
            money,
            publisher,
            Arc::new(|| {
                static RT: std::sync::OnceLock<tokio::runtime::Runtime> =
                    std::sync::OnceLock::new();
                RT.get_or_init(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .build()
                        .expect("a test runtime")
                })
                .handle()
                .clone()
            }),
        );

        let _ = seam.authorize_and_sign(Vec::new(), true);

        let held = seen.lock().unwrap().clone();
        held.expect("a narrative must be staged before the money path is read")
    }

    /// **A node that went away mid-session stops the window promising a broadcast.**
    ///
    /// # The defect this pins
    ///
    /// `install_node_endpoint` was the slot's only writer and only ever assigned `Some`, so the slot
    /// was a **write-only latch**: once any endpoint had been installed, `publisher.is_some()`
    /// answered `true` forever. And it proves less than it looks — [`ControlSpendPublisher::new`]
    /// does no I/O, so it succeeds against a dead address exactly as against a live one.
    ///
    /// dig-app is long-lived and dig-node restarts on the beacon's nightly update, so
    /// connected-then-gone is the ORDINARY case. In it, a `broadcast: true` spend showed the
    /// irrevocable-send wording, pushed nothing, and handed the signed bundle back to the dapp — free
    /// to broadcast whenever it liked, while the person believed the payment had already left.
    ///
    /// # Why the fixture varies install-then-retract against install-and-hold
    ///
    /// `broadcast` is `true` in BOTH arms, and both arms INSTALL first. The nearest wrong
    /// implementation reads *whether an endpoint was ever installed* rather than whether one is
    /// installed NOW, so an arm that never installed at all would pass with the latch bug fully
    /// present — it is the retraction, not the absence, that distinguishes them.
    ///
    /// It drives [`live_publisher_source`], the real production source, rather than a double: the
    /// defect lived in the latch that source reads, so a double would have tested the wrong thing.
    ///
    /// Both arms run inside ONE test because the slot is process-wide; splitting them would let the
    /// test runner interleave two tests mutating the same static.
    #[test]
    fn a_node_that_went_away_stops_the_window_promising_a_broadcast() {
        const ENDPOINT: &str = "http://127.0.0.1:4161";

        // CONTROL — installed and still connected. This must promise the send, or the assertion
        // below would pass for an implementation that never promises one at all.
        install_node_endpoint(ENDPOINT);
        assert!(
            node_endpoint().is_some(),
            "the fixture must have actually installed an endpoint"
        );
        let while_connected = narrative_staged_by(live_publisher_source());
        assert!(
            while_connected.headline.contains("SEND"),
            "control: with a node connected the window must say the payment will be sent: {}",
            while_connected.headline
        );

        // The node goes away. Everything else is identical, including `broadcast: true`.
        clear_node_endpoint();
        assert!(
            node_endpoint().is_none(),
            "retracting the endpoint must actually clear the slot -- a one-way writer is the whole              defect"
        );
        let after_it_went_away = narrative_staged_by(live_publisher_source());
        assert!(
            !after_it_went_away.headline.contains("SEND"),
            "a node that has gone cannot be broadcast through, so the window must not say DIG will:              {}",
            after_it_went_away.headline
        );
        assert!(
            !after_it_went_away
                .caution
                .as_deref()
                .is_some_and(|c| c.contains("cannot be recalled")),
            "and it must not warn about an irrevocability it is not about to create -- the bundle              goes back to the dapp, and whether it is ever sent is not settled here: {:?}",
            after_it_went_away.caution
        );
    }

    /// **The seam works when called the way PRODUCTION calls it: from inside a runtime task.**
    ///
    /// # The defect this pins, and why every other test on this module was blind to it
    ///
    /// The loopback server runs the frame handler inside a spawned async task on a current-thread
    /// runtime, and this seam is synchronous, so `authorize_and_sign` executes WHILE that thread is
    /// driving tasks. `Handle::block_on` refuses that outright:
    ///
    /// ```text
    /// Cannot start a runtime from within a runtime.
    /// ```
    ///
    /// The result was a brand-new money wire that panicked on its FIRST use in production. Every unit
    /// test called the seam from an ordinary thread, where `block_on` is entirely legal — so the whole
    /// suite was green while the only path a user could reach was unreachable.
    ///
    /// # Why the fixture nests two runtimes
    ///
    /// That nesting IS the defect. A test that calls the seam directly cannot express it, no matter
    /// what it asserts, because the panic is a property of the CALLING CONTEXT rather than of the
    /// arguments. So the outer current-thread runtime and the spawned task are the production shape
    /// reproduced, and the assertion is simply that the call returns at all.
    ///
    /// It reaches the money source (returning `None` → `LOCKED`), which is past the bridge: the panic
    /// happened at the `block_on`, so any outcome other than a panic proves the bridge was crossed.
    #[test]
    fn the_seam_returns_rather_than_panicking_when_called_from_inside_a_runtime_task() {
        let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw = Arc::clone(&reached);
        let money: MoneyPathSource<
            crate::account::auth::HarnessAuthProvider<crate::account::ceremony::PromptedCeremony>,
        > = Arc::new(move |_| {
            saw.store(true, std::sync::atomic::Ordering::SeqCst);
            None
        });

        let seam = DappSpendAuthority::new(
            money,
            Arc::new(|| Some(CountingPublisher::accepting())),
            live_runtime_source_for_test(),
        );

        // The production nesting: a current-thread runtime driving a spawned task, which calls the
        // synchronous seam.
        let server = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a server runtime");
        let outcome = server.block_on(async move {
            tokio::spawn(async move { seam.authorize_and_sign(Vec::new(), true) })
                .await
                .expect("the frame task must not panic -- a panic here IS the defect")
        });

        assert!(
            reached.load(std::sync::atomic::Ordering::SeqCst),
            "the call must have reached the money source, or it never crossed the bridge at all"
        );
        assert!(
            matches!(outcome, Err(SpendRefusal::Locked)),
            "a locked money source refuses LOCKED; anything else means the fixture drifted:              {outcome:?}"
        );
    }

    /// A runtime source for tests, mirroring the production one: a separate multi-thread runtime,
    /// created once and reused, whose handle outlives every spend.
    fn live_runtime_source_for_test() -> RuntimeSource {
        Arc::new(|| {
            static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
            RT.get_or_init(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .expect("a signing runtime")
            })
            .handle()
            .clone()
        })
    }
}
