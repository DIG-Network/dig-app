//! Sending XCH: the one flow that moves a user's money out of their wallet (dig_ecosystem#2819).
//!
//! Nothing here is new custody machinery. Every piece already existed and this module is the wiring
//! between them, in the one order that is safe:
//!
//! 1. **build** — [`WalletOps::build_transfer`](dig_account::WalletOps::build_transfer) selects the
//!    input coins and produces the unsigned spends, through
//!    [`AccountResidency::build_transfer`](crate::account::residency::AccountResidency::build_transfer)
//!    so a locked account builds nothing.
//! 2. **sign** — [`MoneyPath::authorize_and_sign`](crate::account::money::MoneyPath::authorize_and_sign):
//!    the custody gate rules on the spends it is handed, the human agrees, and only then is anything
//!    signed. This step can take as long as a person takes.
//! 3. **anchor** — [`TransferPlan::pushed_now`](dig_account::TransferPlan::pushed_now) reads the chain
//!    peak, AFTER the signature and immediately before the push.
//! 4. **push** — [`DetailedSpendPublisher::push_detailed`] hands the SIGNED bytes to the node.
//!
//! # Why the push goes through the DETAILED seam
//!
//! The flattening [`SpendPublisher::push`](dig_account::mint::SpendPublisher::push) reports every
//! failure as one `ChainUnavailable`, and this module has to tell two very different situations
//! apart: a push that provably never left (no control token, an older node, a node that refused the
//! credential) and one nobody can rule on (nothing answered, or the answer never came). The first is
//! a plain failure — nothing was sent, and the person may simply try again. The second is
//! [`SendError::PushUnanswered`], which holds the Send control closed because a second transfer
//! could pay the recipient twice. Flattened, all six become the second, and Send is dead for the
//! rest of the process on the two most likely first-run faults.
//!
//! # Why the peak is read between signing and pushing, and not anywhere else
//!
//! The peak is the height a later confirmation must not predate — the only thing that makes a
//! back-dated confirmation contradict something the chain itself said BEFORE it saw the bundle
//! (`dig-account`'s [`TransferPlan::pushed_at`](dig_account::TransferPlan::pushed_at) states the rule).
//! Read before the confirm ceremony, it would be minutes or hours stale by the time the bundle is
//! broadcast, and every block in that window would become a height a dishonest source could place an
//! invented confirmation at. Read after the push, the check is worthless outright. So the read sits in
//! the narrow gap, and if it FAILS this module refuses to push at all rather than anchoring at `0` —
//! a zero anchor makes the back-dating check vacuous, because every height is at or above genesis.
//!
//! # There is no retry and no fee bump in this module, deliberately
//!
//! A future retry MUST go through
//! [`WalletOps::build_transfer_replacing`](dig_account::WalletOps::build_transfer_replacing), which
//! reuses the ORIGINAL transfer's inputs. A retry built with a plain `build_transfer` can pay the
//! recipient TWICE: coin selection picks its lead coin by `amount + fee`, so a bumped fee can cross a
//! coin boundary onto a different input set, and two bundles spending disjoint inputs can both
//! confirm. Since this module exposes no retry at all, that hazard cannot arise here — which is the
//! reason it exposes none.
//!
//! # XCH only
//!
//! CAT / $DIG sending is a separate builder ([`dig_account::CatTransferRequest`]) and is not wired
//! here.
//!
//! # The custody boundary (§908)
//!
//! Signing happens in-process, inside `dig-account`'s signer. What crosses to the node is an
//! already-signed [`SpendBundle`](chia_protocol::SpendBundle) and nothing else; the node signs
//! nothing and is never asked to.

use dig_account::mint::PushOutcome;
use dig_account::{AuthProvider, TransferResult};
use dig_account::{
    CustodyPolicy, PendingTransfer, SpendOpClass, TransferError, TransferRequest, TransferStatus,
};
use dig_chainsource_interface::ChainSource;

use crate::account::money::{MoneyPath, MoneyPathError};
use crate::account::residency::AccountResidency;
use crate::chain::{DetailedSpendPublisher, PublishFailure};

/// The fee every send in this app pays, in mojos (0.000001 XCH).
///
/// A FIXED, displayed number rather than an estimate. The confirm ceremony shows the fee on its own
/// line, and what it shows is exactly what will be paid — a fact, not a guess. An "recommended fee"
/// derived from mempool pressure would put a number in front of the user that the app cannot promise,
/// and a user who has agreed to a fee has agreed to *this* one.
///
/// Small enough to be unremarkable on mainnet and non-zero so a busy mempool still has a reason to
/// include the bundle.
pub const DEFAULT_SEND_FEE_MOJOS: u64 = 1_000_000;

/// Why a send did not reach the chain.
///
/// # The one distinction that matters, and it is exact in both directions
///
/// [`PushUnanswered`](Self::PushUnanswered) is the ONLY variant whose outcome is unknown: a bundle
/// may be in a mempool, so it must be watched and must never be rebuilt. Every OTHER variant means
/// **no bundle was broadcast** — the money has not moved, nothing needs watching, and offering the
/// form again is safe.
///
/// The converse half is what [`PushNotSent`](Self::PushNotSent) exists for. Before it, a push that
/// was refused locally or declined by the node arrived here as `PushUnanswered` too, which made the
/// sentence above true only one way round: an unknown outcome was always `PushUnanswered`, but a
/// `PushUnanswered` was frequently a plain, knowable failure — and each one held the Send control
/// closed for the rest of the process over a bundle that had provably never left.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// The account is locked. Nothing was built, nothing was signed, nothing was pushed.
    #[error("the account is locked — nothing was sent")]
    Locked,

    /// The wallet this unlock derives is not the active profile's, so a send would spend from the
    /// identity the user just switched away from. Fail-closed (dig_ecosystem#2496).
    #[error("the wallet is pinned behind the active profile — nothing was sent: {0}")]
    WalletBehindActiveProfile(String),

    /// The unsigned transfer could not be built — insufficient funds, an unpayable destination, a
    /// chain read that failed. `dig-account` decides; this only carries its verdict.
    #[error("could not build the transfer: {0}")]
    Build(#[from] TransferError),

    /// The custody gate refused, the user declined, or signing failed. No bundle exists.
    #[error("the transfer was not signed: {0}")]
    Sign(#[from] MoneyPathError),

    /// The pre-push peak could not be read, so the transfer was **not pushed**.
    ///
    /// Deliberately fatal rather than defaulted: see the [module docs](self) on why a `0` anchor is
    /// worse than not sending.
    #[error("could not read the chain peak before pushing, so nothing was pushed: {0}")]
    PeakUnreadable(TransferError),

    /// A mempool judged the bundle and said NO. The money did not move, and the remedy is to build a
    /// new transfer — never to re-push these bytes.
    #[error("the network rejected the transfer: {reason}")]
    Rejected {
        /// The node's stated reason.
        reason: String,
    },

    /// The bundle was **not broadcast**, and could not have been: it never went out, or the node
    /// ANSWERED declining to take it.
    ///
    /// Every one of these is decided before a mempool could hold anything —
    /// [`PublishFailure::may_have_reached_a_mempool`] is where that judgement is made and why. A
    /// person sees a plain failure and the form comes back, because there is nothing in flight for a
    /// second send to collide with. The two most likely of them on a first run — no control token
    /// and a dig-node too old to serve the method — are precisely why this is not folded into
    /// [`PushUnanswered`](Self::PushUnanswered).
    #[error("the transfer was not broadcast: {0}")]
    PushNotSent(#[source] PublishFailure),

    /// The push was never JUDGED: the node could not be asked, or did not answer.
    ///
    /// The outcome is UNKNOWN, not "no". The bundle may be in a mempool already, so this carries the
    /// [`PendingTransfer`] and the caller's only safe move is to POLL it with
    /// [`transfer_status`](dig_account::transfer_status). Rebuilding instead could pay twice.
    #[error("the node did not answer the broadcast, so this transfer's fate is unknown: {detail}")]
    PushUnanswered {
        /// Poll this rather than rebuilding.
        pending: Box<PendingTransfer>,
        /// What went wrong asking.
        detail: String,
    },
}

/// Everything one send needs, held together so a send is one call rather than a sequence a caller
/// could get out of order.
///
/// # One send at a time, structurally
///
/// [`send`](Self::send) takes `self` **by value**. Starting a send therefore consumes the session,
/// and a caller holding one [`InFlightSend`] has no session left to start a second send with — the
/// compiler rejects it rather than a runtime flag someone forgets to check. Getting a session back
/// means going through [`InFlightSend::finish`], which is where a caller states that the previous
/// transfer is resolved.
///
/// A FAILED send consumes the session too. That is not an oversight: an owner who wants to try again
/// asks the residency for a fresh session, which re-reads the account (and so re-observes a lock that
/// landed in the meantime) instead of reusing a handle assembled before the failure.
pub struct SendSession<'a, C, Pub, P>
where
    C: ChainSource + ?Sized,
    Pub: DetailedSpendPublisher + ?Sized,
    P: AuthProvider,
{
    residency: &'a AccountResidency,
    money: &'a MoneyPath<P>,
    custody: CustodyPolicy,
    chain: &'a C,
    publisher: &'a Pub,
}

impl<'a, C, Pub, P> SendSession<'a, C, Pub, P>
where
    C: ChainSource + ?Sized,
    Pub: DetailedSpendPublisher + ?Sized,
    P: AuthProvider,
{
    /// Assemble a session over the live account, its money gate, and the node's two chain seams.
    ///
    /// `custody` is the profile's persisted tier; it is the same policy the `money` gate was built
    /// with, and it is passed to the builder so a vault profile is refused at build time by name
    /// rather than at the gate.
    pub fn new(
        residency: &'a AccountResidency,
        money: &'a MoneyPath<P>,
        custody: CustodyPolicy,
        chain: &'a C,
        publisher: &'a Pub,
    ) -> Self {
        Self {
            residency,
            money,
            custody,
            chain,
            publisher,
        }
    }

    /// Build, gate, sign, anchor and push `request` — the whole send, in the one safe order.
    ///
    /// Returns an [`InFlightSend`] ONLY when a mempool accepted the bundle. That is an acceptance and
    /// not a payment: the money is settled when, and only when, polling reports
    /// [`TransferStatus::Confirmed`].
    ///
    /// The op class is [`SpendOpClass::SmallSend`] because the destination and amount were typed by
    /// the user in this process, which makes it a DECLARED payment. `AutoSendPolicy` denies every
    /// class by default, so this still reaches the confirm ceremony unless the user has deliberately
    /// configured otherwise — in which case they get what they configured.
    pub async fn send(self, request: &TransferRequest) -> Result<InFlightSend, SendError> {
        let plan = self
            .residency
            .build_transfer(self.chain, &self.custody, request)
            .ok_or(SendError::Locked)??;

        // Sign FIRST. The human is in this call, and it may take minutes.
        let bundle = self
            .money
            .authorize_and_sign(plan.coin_spends().to_vec(), SpendOpClass::SmallSend)
            .await?;

        // Then anchor, in the gap between the signature and the broadcast. A failure here refuses
        // the push: an unanchored transfer cannot tell a back-dated confirmation from a real one.
        let pending = plan
            .pushed_now(self.chain)
            .map_err(SendError::PeakUnreadable)?;

        match self.publisher.push_detailed(&bundle) {
            Ok(PushOutcome::Accepted | PushOutcome::AlreadyInMempool) => {
                Ok(InFlightSend { pending })
            }
            Ok(PushOutcome::Rejected { reason }) => Err(SendError::Rejected { reason }),
            // The bundle may be in a mempool, so the transfer survives to be POLLED. Rebuilding it
            // is the one action that can pay the recipient twice.
            Err(failure) if failure.may_have_reached_a_mempool() => {
                Err(SendError::PushUnanswered {
                    pending: Box::new(pending),
                    detail: failure.to_string(),
                })
            }
            // It provably never left, so there is nothing to watch and the form may come back.
            Err(failure) => Err(SendError::PushNotSent(failure)),
        }
    }
}

/// A transfer a mempool has accepted and the chain has not yet settled.
///
/// It deliberately reports NOTHING that could be read as success. The only value meaning *the money
/// arrived* is `dig-account`'s [`ConfirmedTransfer`](dig_account::ConfirmedTransfer), which is
/// constructible only inside that crate from a buried chain record — so this type cannot produce one,
/// and neither can any caller.
#[derive(Debug)]
#[must_use = "an accepted push is not a payment; poll `status` until it confirms"]
pub struct InFlightSend {
    pending: PendingTransfer,
}

impl InFlightSend {
    /// What the chain says about this transfer right now.
    ///
    /// A poll, not a subscription: `Awaiting` is the ordinary answer for the first several blocks,
    /// and `Failed` is terminal (a source coin went to a different spend, so these bytes can never be
    /// included).
    pub fn status<S>(&self, chain: &S) -> TransferResult<TransferStatus>
    where
        S: ChainSource + ?Sized,
    {
        dig_account::transfer_status(&self.pending, chain)
    }

    /// The transfer being watched — its payment coin id, its inputs, and the height it was pushed at.
    pub fn pending(&self) -> &PendingTransfer {
        &self.pending
    }

    /// Give up watching, freeing the caller to start another send.
    ///
    /// Nothing is verified here: a caller that discards an unresolved transfer is making a statement
    /// about its own bookkeeping, and this is where that statement is written down. The transfer's
    /// [`PendingTransfer`] comes back so it can still be polled afterwards by whoever kept it.
    pub fn finish(self) -> PendingTransfer {
        self.pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::active_profile::WalletSlot;
    use crate::account::auth::{AuthCeremony, CeremonyError, HarnessAuthProvider};
    use async_trait::async_trait;
    use chia_protocol::{Bytes32, Coin, SpendBundle};
    use dig_account::mint::MIN_CONFIRMATION_DEPTH;
    use dig_account::{
        AccountId, AuthFactors, AutoSendPolicy, HotWallet, ProfileIx, SpendDecision, SpendSummary,
        SystemClock,
    };
    use dig_chainsource_interface::{ChainSourceError, CoinRecord, MockChainSource};
    use dig_wallet_backend::types::Network;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    /// A plausible mainnet height, so nothing passes merely because the numbers are small.
    const PEAK: u32 = 5_412_009;

    /// Enough to pay the amount and the fee several times over.
    const FUNDED_MOJOS: u64 = 100_000_000;

    /// The amount every fixture sends.
    const AMOUNT: u64 = 250_000;

    /// A destination that is emphatically not the sending wallet.
    const RECIPIENT: Bytes32 = Bytes32::new([9; 32]);

    /// The steps a send takes, in the order they actually happened.
    ///
    /// Order is the property under test, so it is RECORDED rather than asserted per-call: a test that
    /// only counted calls could not tell the safe order from the two unsafe ones.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Step {
        /// The human agreed at the confirm ceremony — the last thing before the signature.
        Confirmed,
        /// A peak read.
        PeakRead,
        /// The signed bundle went to the publisher.
        Pushed,
    }

    type Journal = Arc<Mutex<Vec<Step>>>;

    /// A chain that answers from a [`MockChainSource`] and writes every peak read into the journal,
    /// optionally refusing the peak alone.
    ///
    /// It wraps rather than replaces the canonical mock: the fixture chain, the coin records and the
    /// fail-closed behaviour are all the mock's, and this adds only the two things the mock cannot
    /// express — observation, and a failure scoped to `peak_height`.
    struct WatchedChain {
        inner: MockChainSource,
        journal: Journal,
        peak_fails: bool,
    }

    impl WatchedChain {
        fn new(inner: MockChainSource, journal: Journal) -> Self {
            Self {
                inner,
                journal,
                peak_fails: false,
            }
        }

        /// The same chain, except the peak read fails. Every other read still answers, so a refusal
        /// here can only come from the peak.
        fn with_unreadable_peak(mut self) -> Self {
            self.peak_fails = true;
            self
        }
    }

    impl ChainSource for WatchedChain {
        type Error = ChainSourceError;

        fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            self.inner.coin_record(coin_id)
        }

        fn coin_records_by_puzzle_hash(
            &self,
            puzzle_hash: Bytes32,
            include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            self.inner
                .coin_records_by_puzzle_hash(puzzle_hash, include_spent)
        }

        fn coin_records_by_parent(
            &self,
            parent_coin_id: Bytes32,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            self.inner.coin_records_by_parent(parent_coin_id)
        }

        fn coin_spend(
            &self,
            coin_id: Bytes32,
        ) -> Result<Option<chia_protocol::CoinSpend>, Self::Error> {
            self.inner.coin_spend(coin_id)
        }

        fn resolve_singleton_lineage(
            &self,
            launcher_id: Bytes32,
        ) -> Result<Option<dig_chainsource_interface::SingletonLineage>, Self::Error> {
            self.inner.resolve_singleton_lineage(launcher_id)
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            self.journal.lock().unwrap().push(Step::PeakRead);
            if self.peak_fails {
                return Err(ChainSourceError::Timeout);
            }
            self.inner.peak_height()
        }

        fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
            self.inner.block_timestamp(height)
        }
    }

    /// A publisher that journals its pushes and answers with a scripted outcome.
    struct ScriptedPublisher {
        journal: Journal,
        answer: RefCell<Option<Result<PushOutcome, PublishFailure>>>,
        pushed: RefCell<Vec<SpendBundle>>,
    }

    impl ScriptedPublisher {
        fn answering(journal: Journal, answer: Result<PushOutcome, PublishFailure>) -> Self {
            Self {
                journal,
                answer: RefCell::new(Some(answer)),
                pushed: RefCell::new(Vec::new()),
            }
        }

        fn accepting(journal: Journal) -> Self {
            Self::answering(journal, Ok(PushOutcome::Accepted))
        }

        fn pushes(&self) -> usize {
            self.pushed.borrow().len()
        }
    }

    impl DetailedSpendPublisher for ScriptedPublisher {
        fn push_detailed(&self, bundle: &SpendBundle) -> Result<PushOutcome, PublishFailure> {
            self.journal.lock().unwrap().push(Step::Pushed);
            self.pushed.borrow_mut().push(bundle.clone());
            self.answer
                .borrow_mut()
                .take()
                .unwrap_or(Ok(PushOutcome::Accepted))
        }
    }

    /// The confirm ceremony, journalled. It approves, because a decline would stop the flow before
    /// the steps this module is responsible for ordering.
    struct JournallingCeremony {
        journal: Journal,
    }

    #[async_trait]
    impl AuthCeremony for JournallingCeremony {
        async fn collect_unlock_factors(
            &self,
            _account: &AccountId,
            _reason: Option<&str>,
        ) -> Result<AuthFactors, CeremonyError> {
            Err(CeremonyError::Unavailable("not an unlock test".into()))
        }

        async fn confirm_spend(
            &self,
            _account: &AccountId,
            _profile: ProfileIx,
            _summary: &SpendSummary,
        ) -> Result<SpendDecision, CeremonyError> {
            self.journal.lock().unwrap().push(Step::Confirmed);
            Ok(SpendDecision::Approve)
        }
    }

    /// A funded account plus the chain its wallet lives on, assembled together because the input coin
    /// must sit at the puzzle hash THIS account derives.
    struct Bench {
        residency: AccountResidency,
        money: MoneyPath<HarnessAuthProvider<JournallingCeremony>>,
        journal: Journal,
        funding: Coin,
    }

    impl Bench {
        fn funded() -> Self {
            let journal: Journal = Arc::new(Mutex::new(Vec::new()));
            let residency = crate::account::residency::test_support::residency();
            let puzzle_hash = residency
                .wallet_puzzle_hash_for_test()
                .expect("a fresh residency is unlocked");
            let money = MoneyPath::new(
                residency.clone(),
                HarnessAuthProvider::new(JournallingCeremony {
                    journal: journal.clone(),
                }),
                AccountId::new("send-test"),
                Network::Mainnet,
                CustodyPolicy::Hot(HotWallet::default()),
                AutoSendPolicy::default(),
                Arc::new(SystemClock),
            )
            .expect("an unlocked residency yields a money path");
            Self {
                funding: Coin::new(Bytes32::new([7; 32]), puzzle_hash, FUNDED_MOJOS),
                residency,
                money,
                journal,
            }
        }

        /// The chain before the send: a peak and one spendable coin.
        fn chain(&self) -> WatchedChain {
            WatchedChain::new(
                MockChainSource::new()
                    .with_peak(PEAK)
                    .with_coin(self.funding.coin_id(), confirmed(self.funding, PEAK - 100)),
                self.journal.clone(),
            )
        }

        fn session<'a>(
            &'a self,
            chain: &'a WatchedChain,
            publisher: &'a ScriptedPublisher,
        ) -> SendSession<
            'a,
            WatchedChain,
            ScriptedPublisher,
            HarnessAuthProvider<JournallingCeremony>,
        > {
            SendSession::new(
                &self.residency,
                &self.money,
                CustodyPolicy::Hot(HotWallet::default()),
                chain,
                publisher,
            )
        }

        fn steps(&self) -> Vec<Step> {
            self.journal.lock().unwrap().clone()
        }
    }

    fn confirmed(coin: Coin, height: u32) -> CoinRecord {
        CoinRecord {
            coin,
            confirmed_height: Some(height),
            spent_height: None,
            timestamp: None,
            coinbase: false,
        }
    }

    /// A push whose fate is genuinely undecidable: the bytes may have gone out before the connection
    /// died.
    fn unanswered() -> PublishFailure {
        PublishFailure::Unreachable {
            detail: "the node did not answer".to_string(),
        }
    }

    fn request() -> TransferRequest {
        TransferRequest::new(
            dig_account::PayableDestination::from_derived(RECIPIENT),
            AMOUNT,
        )
        .with_fee(DEFAULT_SEND_FEE_MOJOS)
    }

    /// The ordering invariant, asserted as an ORDER and not as a set of calls.
    ///
    /// The build reads the chain too, so simply observing "a peak was read" proves nothing. What is
    /// asserted is the peak read that PRECEDES the push: it must fall after the human confirmed and
    /// before the bundle went out. Both wrong orders — anchoring before the ceremony, and anchoring
    /// after the broadcast — produce a different sequence here and fail.
    #[tokio::test]
    async fn the_peak_is_read_after_signing_and_immediately_before_the_push() {
        let bench = Bench::funded();
        let chain = bench.chain();
        let publisher = ScriptedPublisher::accepting(bench.journal.clone());

        let _accepted = bench
            .session(&chain, &publisher)
            .send(&request())
            .await
            .expect("a funded, approved send is accepted");

        let steps = bench.steps();
        let pushed_at = steps
            .iter()
            .position(|s| *s == Step::Pushed)
            .expect("the bundle was pushed");
        let confirmed_at = steps
            .iter()
            .position(|s| *s == Step::Confirmed)
            .expect("the human confirmed");
        let anchor_at = steps[..pushed_at]
            .iter()
            .rposition(|s| *s == Step::PeakRead)
            .expect("a peak was read before the push");

        assert!(
            confirmed_at < anchor_at,
            "the anchoring peak must be read AFTER the signature, got {steps:?}"
        );
        assert_eq!(
            anchor_at + 1,
            pushed_at,
            "the anchoring peak must be the last thing before the push, got {steps:?}"
        );
    }

    /// A peak that cannot be read means NOTHING is broadcast — never an anchor of `0`.
    #[tokio::test]
    async fn an_unreadable_peak_pushes_nothing() {
        let bench = Bench::funded();
        let chain = bench.chain().with_unreadable_peak();
        let publisher = ScriptedPublisher::accepting(bench.journal.clone());

        let error = bench
            .session(&chain, &publisher)
            .send(&request())
            .await
            .expect_err("an unreadable peak refuses the send");

        assert!(
            matches!(error, SendError::PeakUnreadable(_)),
            "expected a peak failure, got {error:?}"
        );
        assert_eq!(publisher.pushes(), 0, "nothing may be broadcast unanchored");
    }

    /// A locked account signs nothing and pushes nothing — the build never happens.
    #[tokio::test]
    async fn a_locked_account_sends_nothing() {
        let bench = Bench::funded();
        let chain = bench.chain();
        let publisher = ScriptedPublisher::accepting(bench.journal.clone());
        crate::session_lock::SessionKeys::lock_all(&bench.residency);

        let error = bench
            .session(&chain, &publisher)
            .send(&request())
            .await
            .expect_err("a locked account cannot send");

        assert!(
            matches!(error, SendError::Locked),
            "expected a locked refusal, got {error:?}"
        );
        assert_eq!(publisher.pushes(), 0);
        assert!(
            !bench.steps().contains(&Step::Confirmed),
            "a locked account must not even reach the confirm ceremony"
        );
    }

    /// A mempool that says no yields an error and NOTHING a caller can read as a payment.
    #[tokio::test]
    async fn a_rejected_broadcast_yields_nothing_readable_as_success() {
        let bench = Bench::funded();
        let chain = bench.chain();
        let publisher = ScriptedPublisher::answering(
            bench.journal.clone(),
            Ok(PushOutcome::Rejected {
                reason: "DOUBLE_SPEND".to_owned(),
            }),
        );

        let error = bench
            .session(&chain, &publisher)
            .send(&request())
            .await
            .expect_err("a rejected bundle is not a send");

        assert!(
            matches!(&error, SendError::Rejected { reason } if reason == "DOUBLE_SPEND"),
            "expected the node's rejection, got {error:?}"
        );
    }

    /// An unanswered push hands back the pending transfer to POLL, because its fate is unknown and
    /// rebuilding could pay twice.
    #[tokio::test]
    async fn an_unanswered_push_reports_an_unknown_fate_and_hands_back_the_pending_transfer() {
        let bench = Bench::funded();
        let chain = bench.chain();
        let publisher = ScriptedPublisher::answering(bench.journal.clone(), Err(unanswered()));

        let error = bench
            .session(&chain, &publisher)
            .send(&request())
            .await
            .expect_err("an unanswered push is not a completed send");

        let SendError::PushUnanswered { pending, .. } = error else {
            panic!("expected an unanswered push, got {error:?}");
        };
        assert_eq!(
            pending.pushed_at_height(),
            PEAK,
            "the anchor must survive so the caller can poll rather than rebuild"
        );
    }

    /// A pushed transfer reports `Awaiting` — never confirmed — until a BURIED record exists.
    ///
    /// Both halves matter. The shallow chain is the near-miss a depth check must reject; without it,
    /// an implementation that confirmed on the mere existence of the coin would pass just as well.
    #[tokio::test]
    async fn a_pushed_transfer_awaits_until_its_payment_coin_is_buried() {
        let bench = Bench::funded();
        let chain = bench.chain();
        let publisher = ScriptedPublisher::accepting(bench.journal.clone());

        let in_flight = bench
            .session(&chain, &publisher)
            .send(&request())
            .await
            .expect("a funded, approved send is accepted");
        let payment_coin_id = in_flight.pending().payment_coin_id();

        // Nothing on chain yet.
        assert!(
            matches!(
                in_flight.status(&chain).expect("a readable chain"),
                TransferStatus::Awaiting { .. }
            ),
            "an accepted push is not a confirmation"
        );

        // The coin exists, one block deep — real, and not yet buried.
        let payment = Coin::new(bench.funding.coin_id(), RECIPIENT, AMOUNT);
        let shallow = WatchedChain::new(
            MockChainSource::new()
                .with_peak(PEAK + 1)
                .with_coin(payment_coin_id, confirmed(payment, PEAK)),
            bench.journal.clone(),
        );
        assert!(
            matches!(
                in_flight.status(&shallow).expect("a readable chain"),
                TransferStatus::Awaiting { .. }
            ),
            "a coin one block deep is not settled money"
        );

        // Buried.
        let buried = WatchedChain::new(
            MockChainSource::new()
                .with_peak(PEAK + MIN_CONFIRMATION_DEPTH + 1)
                .with_coin(payment_coin_id, confirmed(payment, PEAK)),
            bench.journal.clone(),
        );
        let TransferStatus::Confirmed(settled) =
            in_flight.status(&buried).expect("a readable chain")
        else {
            panic!("a buried payment coin must confirm");
        };
        assert_eq!(settled.confirmed_height(), PEAK);
    }

    /// The fee is a constant the caller passes through unchanged — the send never substitutes an
    /// estimate of its own.
    #[tokio::test]
    async fn the_fee_the_caller_declared_is_the_fee_that_is_spent() {
        let bench = Bench::funded();
        let chain = bench.chain();
        let publisher = ScriptedPublisher::accepting(bench.journal.clone());

        let in_flight = bench
            .session(&chain, &publisher)
            .send(&request())
            .await
            .expect("a funded, approved send is accepted");

        assert_eq!(in_flight.pending().fee_mojos(), DEFAULT_SEND_FEE_MOJOS);
        assert_eq!(in_flight.pending().amount_mojos(), AMOUNT);
    }

    /// A wallet with nothing in it refuses at the BUILD, before any ceremony and any push.
    #[tokio::test]
    async fn an_empty_wallet_refuses_before_the_ceremony() {
        let bench = Bench::funded();
        let chain = WatchedChain::new(
            MockChainSource::new().with_peak(PEAK),
            bench.journal.clone(),
        );
        let publisher = ScriptedPublisher::accepting(bench.journal.clone());

        let error = bench
            .session(&chain, &publisher)
            .send(&request())
            .await
            .expect_err("an empty wallet cannot fund a transfer");

        assert!(
            matches!(
                error,
                SendError::Build(TransferError::InsufficientFunds { .. })
            ),
            "expected a shortfall, got {error:?}"
        );
        assert_eq!(publisher.pushes(), 0);
        assert!(!bench.steps().contains(&Step::Confirmed));
    }

    /// **An unanswered push reaches the surface as an UNKNOWN outcome carrying its coin id — never as
    /// a failure** (dig_ecosystem#2819).
    ///
    /// This lives here, beside the bench, because a [`PendingTransfer`] can only be obtained by
    /// performing a real send: dig-account constructs one from a plan and a peak, and there is no
    /// hatch. A test of the mapping alone would have to invent one, and the invented value is exactly
    /// the part that matters — the coin id the person is told to watch.
    #[tokio::test]
    async fn an_unanswered_push_surfaces_as_an_unknown_outcome_naming_the_coin_to_watch() {
        use crate::wallet::sending::SendProgress;

        let bench = Bench::funded();
        let chain = bench.chain();
        let publisher = ScriptedPublisher::answering(bench.journal.clone(), Err(unanswered()));

        let error = bench
            .session(&chain, &publisher)
            .send(&request())
            .await
            .expect_err("an unanswered push is not a completed send");
        let SendError::PushUnanswered { pending, .. } = &error else {
            panic!("expected an unanswered push, got {error:?}");
        };
        let coin_id = pending.payment_coin_id().to_string();

        let progress = SendProgress::of_error(&error);
        assert_eq!(
            progress,
            SendProgress::Unknown {
                payment_coin_id: coin_id,
                detail: unanswered().to_string(),
            },
            "an unknown outcome was flattened into a failure, which invites the one action that can \
             pay the recipient twice"
        );
        assert!(
            progress.in_flight(),
            "an unknown outcome must keep the Send control refused"
        );
    }

    /// **A pushed transfer reads as pending until it is buried, and only then as confirmed**
    /// (dig_ecosystem#2819).
    ///
    /// The surface's half of `a_pushed_transfer_awaits_until_its_payment_coin_is_buried`: the same
    /// three chains, asserted through the projection a person actually reads. The shallow chain is the
    /// near-miss — a projection that reported success on the coin merely existing passes without it.
    #[tokio::test]
    async fn a_pushed_transfer_reads_as_pending_until_the_chain_buries_it() {
        use crate::wallet::sending::SendProgress;

        let bench = Bench::funded();
        let chain = bench.chain();
        let publisher = ScriptedPublisher::accepting(bench.journal.clone());
        let in_flight = bench
            .session(&chain, &publisher)
            .send(&request())
            .await
            .expect("a funded, approved send is accepted");
        let pending = in_flight.pending();
        let coin_id = pending.payment_coin_id();

        let progress = |chain: &WatchedChain| {
            SendProgress::of_status(pending, &in_flight.status(chain).expect("a readable chain"))
        };
        assert!(
            matches!(progress(&chain), SendProgress::Pending { .. }),
            "an accepted push was shown as something other than pending"
        );

        let payment = Coin::new(bench.funding.coin_id(), RECIPIENT, AMOUNT);
        let shallow = WatchedChain::new(
            MockChainSource::new()
                .with_peak(PEAK + 1)
                .with_coin(coin_id, confirmed(payment, PEAK)),
            bench.journal.clone(),
        );
        let SendProgress::Pending {
            blocks_since_push, ..
        } = progress(&shallow)
        else {
            panic!("a coin one block deep was shown as settled money");
        };
        assert_eq!(
            blocks_since_push, 1,
            "the wait must be legible, and one block had passed"
        );

        let buried = WatchedChain::new(
            MockChainSource::new()
                .with_peak(PEAK + MIN_CONFIRMATION_DEPTH + 1)
                .with_coin(coin_id, confirmed(payment, PEAK)),
            bench.journal.clone(),
        );
        assert_eq!(
            progress(&buried),
            SendProgress::Confirmed {
                payment_coin_id: coin_id.to_string(),
                confirmed_height: PEAK,
            }
        );
        assert!(
            !progress(&buried).in_flight(),
            "a settled transfer must free the form for the next send"
        );
    }

    /// **The shell's handle walks a real send from accepted to confirmed, asks the chain no more
    /// often than a block, and never turns a failed read into a failed payment**
    /// (dig_ecosystem#2819).
    ///
    /// Three properties in one fixture because they share one actor and the fixture is a real pushed
    /// transfer. Each is varied against a truthful control:
    ///
    /// - the throttle is asserted against a chain that WOULD say confirmed, so a handle that polled
    ///   every time would visibly move and fail;
    /// - the unreadable chain is asserted between two readable ones, so a handle that treated a read
    ///   failure as a verdict would lose the pending state it later has to report;
    /// - the confirmation is asserted last, proving the throttle delays a poll rather than preventing
    ///   one.
    #[tokio::test]
    async fn the_send_handle_polls_at_most_once_a_block_and_survives_a_chain_it_cannot_read() {
        use crate::wallet::sending::{SendHolder, SendProgress};
        use std::time::{Duration, Instant};

        let bench = Bench::funded();
        let chain = bench.chain();
        let publisher = ScriptedPublisher::accepting(bench.journal.clone());
        let in_flight = bench
            .session(&chain, &publisher)
            .send(&request())
            .await
            .expect("a funded, approved send is accepted");
        let coin_id = in_flight.pending().payment_coin_id();
        let payment = Coin::new(bench.funding.coin_id(), RECIPIENT, AMOUNT);
        let buried = WatchedChain::new(
            MockChainSource::new()
                .with_peak(PEAK + MIN_CONFIRMATION_DEPTH + 1)
                .with_coin(coin_id, confirmed(payment, PEAK)),
            bench.journal.clone(),
        );

        let holder = SendHolder::default();
        assert!(holder.begin(), "an idle holder offers its send slot");
        assert_eq!(holder.progress(), SendProgress::Signing);

        let started = Instant::now();
        holder.accepted(in_flight.finish());
        assert!(
            matches!(holder.progress(), SendProgress::Pending { .. }),
            "an accepted push must read as pending, never as sent"
        );

        // Inside the interval, against a chain that would confirm: the answer must not move.
        assert!(
            matches!(
                holder.observe(&buried, started + Duration::from_secs(1)),
                SendProgress::Pending { .. }
            ),
            "the handle asked the chain again inside a single block"
        );

        // Due, but the chain cannot be read. That is a fact about this app, not about the transfer.
        let unreadable = bench.chain().with_unreadable_peak();
        assert!(
            matches!(
                holder.observe(&unreadable, started + Duration::from_secs(30)),
                SendProgress::Pending { .. }
            ),
            "a chain read that failed was reported as the transfer failing"
        );

        // Due again, and readable: the confirmation lands.
        assert_eq!(
            holder.observe(&buried, started + Duration::from_secs(60)),
            SendProgress::Confirmed {
                payment_coin_id: coin_id.to_string(),
                confirmed_height: PEAK,
            }
        );
        assert!(
            !holder.progress().in_flight(),
            "a confirmed send must free the form for the next one"
        );
    }

    /// **A send that ended without a broadcast stops the watch; one whose push went unanswered keeps
    /// it** (dig_ecosystem#2819).
    ///
    /// The pair is the property. Both actors are real errors off the same bench, and they differ only
    /// in whether a bundle may exist — which is exactly what decides whether there is anything left to
    /// poll. A handle that dropped the watch in both cases would leave a possibly-live transfer
    /// unwatched, and one that kept it in both would poll a coin that was never created.
    #[tokio::test]
    async fn only_a_send_whose_fate_is_unknown_stays_under_watch() {
        use crate::wallet::sending::{SendHolder, SendProgress};

        let bench = Bench::funded();
        let chain = bench.chain();
        let unanswered = bench
            .session(
                &chain,
                &ScriptedPublisher::answering(bench.journal.clone(), Err(unanswered())),
            )
            .send(&request())
            .await
            .expect_err("an unanswered push is not a completed send");

        let holder = SendHolder::default();
        holder.finished(&unanswered);
        assert!(
            matches!(holder.progress(), SendProgress::Unknown { .. }),
            "an unanswered push was shown as something other than an unknown outcome"
        );
        // Still watched, and still UNKNOWN. Driven past the poll interval so a poll really fires:
        // asserting `Pending | Unknown` here accepted the defect that the poll silently promotes an
        // unjudged transfer, and an `Instant::now()` inside the interval polled nothing at all.
        assert!(
            matches!(
                holder.observe(
                    &chain,
                    std::time::Instant::now() + crate::wallet::sending::POLL_INTERVAL * 2
                ),
                SendProgress::Unknown { .. }
            ),
            "an unknown outcome stopped being watched, so nothing can ever resolve it"
        );

        let rejected = SendError::Rejected {
            reason: "DOUBLE_SPEND".to_string(),
        };
        holder.finished(&rejected);
        let after = holder.observe(&chain, std::time::Instant::now());
        assert_eq!(
            after,
            SendProgress::Failed {
                reason: rejected.to_string(),
                payment_coin_id: None,
            },
            "a rejected bundle is still being polled, so a coin that cannot exist is being looked for"
        );
    }

    /// **A push that provably never left leaves Send usable; one whose fate is unknown holds it
    /// closed** (dig_ecosystem#2819).
    ///
    /// The PAIR is the property, and neither half proves anything alone: a test of only the definite
    /// side passes against an implementation that calls every failure definite — which is the
    /// double-payment defect — and a test of only the unknown side passes against the flattening one
    /// this replaces, which is the defect being fixed. So both sides are asserted against each other,
    /// varying nothing but the publisher's answer.
    ///
    /// Every variant is run rather than one from each side, because the classification is the
    /// deliverable and a per-variant mistake is invisible to a sample. The two consequences asserted
    /// are the ones a person actually experiences: whether the error says a bundle may exist, and
    /// whether the **Send** control is still offered.
    #[tokio::test]
    async fn a_push_that_never_left_leaves_send_usable_and_an_unanswered_one_holds_it_closed() {
        use crate::wallet::sending::SendProgress;

        let never_left = [
            PublishFailure::NoToken,
            PublishFailure::Unserializable {
                detail: "not encodable".to_string(),
            },
            PublishFailure::Unsupported {
                detail: "no such method".to_string(),
            },
            PublishFailure::Unauthorized {
                detail: "unknown token".to_string(),
            },
        ];
        let may_be_live = [
            unanswered(),
            PublishFailure::NodeCouldNotAnswer {
                detail: "timed out forwarding the bundle".to_string(),
            },
        ];

        for failure in never_left {
            let bench = Bench::funded();
            let chain = bench.chain();
            let publisher =
                ScriptedPublisher::answering(bench.journal.clone(), Err(failure.clone()));
            let error = bench
                .session(&chain, &publisher)
                .send(&request())
                .await
                .expect_err("a failed push is not a completed send");

            assert!(
                matches!(&error, SendError::PushNotSent(reported) if *reported == failure),
                "{failure:?} was not reported as a bundle that never left, got {error:?}"
            );
            let progress = SendProgress::of_error(&error);
            assert!(
                matches!(progress, SendProgress::Failed { .. }),
                "{failure:?} was shown as something other than a plain failure: {progress:?}"
            );
            assert!(
                !progress.in_flight(),
                "{failure:?} left Send refused for a bundle that was never broadcast"
            );
        }

        for failure in may_be_live {
            let bench = Bench::funded();
            let chain = bench.chain();
            let publisher =
                ScriptedPublisher::answering(bench.journal.clone(), Err(failure.clone()));
            let error = bench
                .session(&chain, &publisher)
                .send(&request())
                .await
                .expect_err("an unanswered push is not a completed send");

            let SendError::PushUnanswered { pending, .. } = &error else {
                panic!("{failure:?} was called a definite failure, which invites a second send: {error:?}");
            };
            let coin_id = pending.payment_coin_id().to_string();
            let progress = SendProgress::of_error(&error);
            assert_eq!(
                progress,
                SendProgress::Unknown {
                    payment_coin_id: coin_id,
                    detail: failure.to_string(),
                },
                "{failure:?} lost the coin id a person is told to watch"
            );
            assert!(
                progress.in_flight(),
                "{failure:?} offered a second send while a bundle may be in a mempool"
            );
        }
    }

    /// **A poll cannot turn a push nobody judged into "the network has taken this payment".**
    ///
    /// `TransferStatus::Awaiting` says only that the payment coin is not on chain yet, which is the
    /// SAME answer a bundle that was never broadcast produces. So an unjudged transfer must stay
    /// [`SendProgress::Unknown`] across a poll, or ten seconds after an unanswered push the person
    /// reads *"the network has taken this payment and is settling it"* about bytes that may never
    /// have left — and on the token-less path, provably did not.
    ///
    /// The judged holder is the control, and it is what makes this test load-bearing: it polls the
    /// SAME chain, where the payment coin is equally absent, and MUST become `Pending`. An
    /// implementation that simply never promoted anything would satisfy the first half and fail here.
    #[tokio::test]
    async fn a_poll_promotes_a_judged_transfer_and_leaves_an_unjudged_one_unknown() {
        use crate::wallet::sending::{SendHolder, SendProgress, POLL_INTERVAL};

        let bench = Bench::funded();
        let chain = bench.chain();
        let unanswered_error = bench
            .session(
                &chain,
                &ScriptedPublisher::answering(bench.journal.clone(), Err(unanswered())),
            )
            .send(&request())
            .await
            .expect_err("an unanswered push is not a completed send");

        let unjudged = SendHolder::default();
        unjudged.finished(&unanswered_error);
        let due = std::time::Instant::now() + POLL_INTERVAL * 2;
        assert!(
            matches!(unjudged.observe(&chain, due), SendProgress::Unknown { .. }),
            "a transfer no mempool accepted was shown as being settled by the network"
        );

        // The control: a genuinely accepted push, polled against the same chain.
        let accepted_bench = Bench::funded();
        let accepted_chain = accepted_bench.chain();
        let in_flight = accepted_bench
            .session(
                &accepted_chain,
                &ScriptedPublisher::accepting(accepted_bench.journal.clone()),
            )
            .send(&request())
            .await
            .expect("a funded, approved send is accepted");

        let judged = SendHolder::default();
        judged.accepted(in_flight.finish());
        assert!(
            matches!(
                judged.observe(&accepted_chain, due),
                SendProgress::Pending { .. }
            ),
            "an accepted push stopped reporting the wait it is actually in"
        );
    }

    /// **A send is refused outright while another is in flight, and the running one is untouched.**
    ///
    /// Asserted through `SendHolder::send` rather than through `begin` alone, because the defect was
    /// a PLACEMENT: the claim existed nowhere on the path a click takes, so the second send ran, and
    /// the first thing it did was erase the pending transfer of the send already under way. A guard
    /// that lived only in `begin` would satisfy a test of `begin`.
    ///
    /// The fixture is the cheapest call that still reaches the guard: `send` with no residency, which
    /// on an idle holder records `Locked` — the control below. On an in-flight holder that same call
    /// must change NOTHING, and the surviving pending transfer is what proves it. It deliberately
    /// does not involve the tray's `ActionWorker`: the guarantee has to hold wherever a send starts.
    #[tokio::test]
    async fn a_send_is_refused_while_another_is_in_flight_and_leaves_it_undisturbed() {
        use crate::agent::AgentStatus;
        use crate::engine::EngineState;
        use crate::wallet::sending::{SendHolder, SendProgress};

        let status = std::sync::Arc::new(std::sync::RwLock::new(AgentStatus {
            running: true,
            engine: EngineState::initial(),
            active_profile: None,
        }));

        let bench = Bench::funded();
        let chain = bench.chain();
        let in_flight = bench
            .session(&chain, &ScriptedPublisher::accepting(bench.journal.clone()))
            .send(&request())
            .await
            .expect("a funded, approved send is accepted");
        let coin_id = in_flight.pending().payment_coin_id().to_string();

        let holder = SendHolder::default();
        holder.accepted(in_flight.finish());
        holder.send(&status, None, &request());

        assert_eq!(
            holder.progress(),
            SendProgress::Pending {
                payment_coin_id: coin_id,
                blocks_since_push: 0,
            },
            "a second send ran while one was in flight and overwrote the transfer being watched"
        );

        // The control: with nothing in flight, that same call is accepted and records its failure.
        let idle = SendHolder::default();
        idle.send(&status, None, &request());
        assert!(
            matches!(idle.progress(), SendProgress::Failed { .. }),
            "an idle holder refused a send, so the guard above proves nothing"
        );
    }

    /// The wallet slot the money path derives at is the one this bench asserts against — a guard so a
    /// later profile-slot change cannot make the fixtures quietly test a different key.
    #[test]
    fn the_bench_wallet_is_the_residency_wallet() {
        let bench = Bench::funded();
        assert_eq!(
            bench.residency.wallet_slot(),
            WalletSlot::unprofiled(),
            "the fixtures fund the slot the account actually derives"
        );
    }
}
