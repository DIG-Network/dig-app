//! Taking an offer, in the one safe order (dig_ecosystem#3077 slice O2).
//!
//! # The order, and why it is this order
//!
//! 1. **refuse early** — a vault-tier profile cannot commit funds to the settlement puzzle, so it is
//!    turned away by [`take_permitted_by`] before a spend is built. The same answer arrives at the
//!    custody gate anyway; getting it here is what lets the control be disabled with a reason instead
//!    of failing in front of a person who has already agreed.
//! 2. **build** — [`dig_offers::take_build`] produces the taker's UNSIGNED coin spends from the exact
//!    bytes the surface summarized.
//! 3. **sign** — [`MoneyPath::authorize_and_sign`](crate::account::money::MoneyPath::authorize_and_sign):
//!    the custody gate re-derives the spend from those bytes, escalates to the human, and signs. This
//!    is the step that may take minutes, and it happens before anything irreversible.
//! 4. **combine** — [`dig_offers::take_combine`] welds the maker's already-signed half onto the
//!    taker's into one atomic settlement bundle. Either both sides settle or neither does.
//! 5. **push** — the node broadcasts it (§908: the node signs nothing).
//!
//! # What this module deliberately does NOT do
//!
//! It reports no settlement. [`TakenOffer`] names a bundle a mempool accepted, which is a statement
//! about a node and not about the chain.
//!
//! **Two mechanisms this module does NOT reach, stated so nobody builds on a promise:**
//!
//! * **The centralized progress modal (dig_ecosystem#3075) does NOT fire for a take.** That modal
//!   observes [`crate::transaction::Feed`] and nothing else, and every producer calls
//!   `Feed::publish` explicitly. This path pushes through `ControlSpendPublisher::push_detailed`
//!   and never publishes, so no modal is raised. The offer card draws its own Working/Broadcast/
//!   Failed states instead — honest, but local.
//! * **No later chain read follows.** A take creates no `InFlightSend`, so nothing performs the
//!   settlement read that `InFlightSend::status` performs for an ordinary send. Whether the swap
//!   settled is currently unobserved by this app.
//!
//! Both gaps are tracked as dig_ecosystem#3111. Do not read this module's honest local states as
//! evidence that centralized progress or settlement follow-up already exist.

use chia_protocol::Coin;
use chia_sdk_driver::SpendContext;
use dig_account::mint::PushOutcome;
use dig_account::{AuthProvider, CustodyPolicy, HotWallet, SpendOpClass};
use dig_offers::TakerFunds;
use indexmap::IndexMap;
use std::marker::PhantomData;

use crate::account::auth::HarnessAuthProvider;
use crate::account::narrative::NarrativeSlot;
use crate::account::ceremony::PromptedCeremony;
use crate::account::money::{MoneyPath, MoneyPathError};
use crate::account::residency::AccountResidency;
use crate::chain::{DetailedSpendPublisher, PublishFailure};
use crate::transaction::{Feed, Stage, Transaction};
use crate::wallet::offer::{take_permitted_by, OfferError, ReviewedOffer};
use crate::wallet::offer_words as copy;

/// A take that did not complete, named by WHICH step stopped it.
///
/// The variants separate the answers a person can act on (fund the wallet, unlock, use a different
/// profile) from the ones they cannot, and separate a refusal from an unanswered push — because only
/// the second leaves a bundle that may yet settle, and retrying THAT is the one action that can pay
/// twice.
#[derive(Debug, thiserror::Error)]
pub enum TakeError {
    /// The account is locked, so nothing could be built or signed. Fail-closed.
    #[error("the account is locked — the offer was not taken")]
    Locked,

    /// No node is connected, so the wallet's coins could not be read and nothing could be pushed.
    #[error("no DIG node is connected, so nothing could be built or broadcast")]
    NoNode,

    /// A node is connected and could not answer what this wallet holds.
    ///
    /// Deliberately not an empty coin list: a read that failed has made no claim about the wallet,
    /// and treating it as "you have nothing" would tell a funded person they cannot afford a swap.
    #[error("this app could not read what your wallet holds: {0}")]
    FundsUnreadable(String),

    /// The offer could not be read, or this profile may not take one at all.
    #[error(transparent)]
    Offer(#[from] OfferError),

    /// The taker's half could not be built — most often because the wallet cannot cover what the
    /// offer requests. `dig-offers` names the shortfall, and that text is carried through verbatim.
    #[error("this offer could not be taken: {0}")]
    Build(String),

    /// The custody gate refused, or the person declined the confirmation. Nothing was signed.
    #[error(transparent)]
    Sign(#[from] MoneyPathError),

    /// A mempool judged the bundle and rejected it. Nothing settles, and nothing is pending.
    #[error("the network rejected the swap: {reason}")]
    Rejected {
        /// The mempool's own words.
        reason: String,
    },

    /// The push was never answered, so the bundle MAY have reached a mempool.
    ///
    /// Distinct from every other error because the remedy differs absolutely: this one must not be
    /// retried blind. Re-taking an offer whose first take is settling is how a person pays twice.
    #[error(
        "the swap was sent and the node did not answer — do not re-take it until you have \
             checked whether it settled: {detail}"
    )]
    PushUnanswered {
        /// What the transport reported.
        detail: String,
    },

    /// The push provably never left this machine, so nothing is pending and it is safe to try again.
    #[error("the swap was not sent: {0}")]
    PushNotSent(#[source] PublishFailure),
}

/// A settlement bundle a mempool has accepted, and the chain has not yet settled.
///
/// It carries no verdict deliberately. "Accepted" says a node took the bytes; whether the swap
/// happened is a question only a later chain read answers, and any type here that implied otherwise
/// would be the money lie this wallet refuses everywhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "an accepted push is not a completed swap; the chain decides that"]
pub struct TakenOffer {
    /// The spend-bundle name (its hash, lowercase hex) — the handle to look the swap up by.
    pub bundle_name: String,
}

/// The taker's spendable funds, as the app knows them.
///
/// XCH only for now. A CAT-funded take needs each coin's lineage proof, which the coins read does not
/// carry, so offering one would be a control that fails at build time — this is stated in the offer
/// surface instead.
#[derive(Debug, Clone, Default)]
pub struct SpendableXch {
    /// Unspent native coins belonging to this account's wallet address.
    pub coins: Vec<Coin>,
}

impl SpendableXch {
    /// Read the unspent native coins paying `puzzle_hash` from `chain`.
    ///
    /// Spent coins are asked for and then dropped rather than excluded at the source, because a
    /// source that answers `include_spent = false` by silently answering nothing is
    /// indistinguishable from a wallet with no coins. Filtering here means the emptiness is one this
    /// app decided from records it actually saw.
    ///
    /// A read ERROR is never an empty wallet: it becomes
    /// [`FundsUnreadable`](TakeError::FundsUnreadable), because an unanswered read has made no claim
    /// about the money and telling a funded person they cannot afford a swap is the lie this wallet
    /// refuses everywhere else.
    pub fn read_from<C>(chain: &C, puzzle_hash: chia_protocol::Bytes32) -> Result<Self, TakeError>
    where
        C: dig_chainsource_interface::ChainSource + ?Sized,
    {
        let records = chain
            .coin_records_by_puzzle_hash(puzzle_hash, true)
            .map_err(|e| TakeError::FundsUnreadable(e.to_string()))?;
        Ok(Self {
            coins: records
                .into_iter()
                .filter(|record| !record.is_spent())
                .map(|record| record.coin)
                .collect(),
        })
    }
}

/// Build, gate, sign, combine and push a take.
///
/// One take at a time is structural: [`take`](Self::take) consumes the session, exactly as
/// [`SendSession`](crate::wallet::send::SendSession) does, so a caller holding a [`TakenOffer`] has no
/// session left to start a second take with.
pub struct TakeSession<'a, Pub, P>
where
    Pub: DetailedSpendPublisher + ?Sized,
    P: AuthProvider,
{
    residency: &'a AccountResidency,
    money: &'a MoneyPath<P>,
    custody: CustodyPolicy,
    publisher: &'a Pub,
}

impl<'a, Pub, P> TakeSession<'a, Pub, P>
where
    Pub: DetailedSpendPublisher + ?Sized,
    P: AuthProvider,
{
    /// Assemble a session over the live account, its money gate, and the node's push seam.
    pub fn new(
        residency: &'a AccountResidency,
        money: &'a MoneyPath<P>,
        custody: CustodyPolicy,
        publisher: &'a Pub,
    ) -> Self {
        Self {
            residency,
            money,
            custody,
            publisher,
        }
    }

    /// Take `reviewed`, funding it from `funds` and reserving `fee` mojos.
    ///
    /// The bytes handed to the builder are [`ReviewedOffer::offer`] — the same bytes the terms on
    /// screen were summarized from — so a person cannot agree to one swap and settle another.
    ///
    /// The op class is [`SpendOpClass::Undeclared`], which can never auto-approve, so every take
    /// reaches the confirm ceremony. That is deliberate and is not a limit to relax later: a swap is
    /// irreversible and moves assets no mojo allowance can weigh, so there is no configured bound
    /// under which approving one without asking would be honest.
    pub async fn take(
        self,
        reviewed: &ReviewedOffer,
        funds: &SpendableXch,
        fee: u64,
    ) -> Result<TakenOffer, TakeError> {
        take_permitted_by(&self.custody)?;
        let (change_puzzle_hash, public_key) =
            self.residency.taker_identity().ok_or(TakeError::Locked)?;

        let mut owner_keys = IndexMap::new();
        owner_keys.insert(change_puzzle_hash, public_key);

        let mut ctx = SpendContext::new();
        let unsigned = dig_offers::take_build(
            &mut ctx,
            reviewed.offer(),
            TakerFunds {
                change_puzzle_hash,
                owner_keys,
                xch_coins: funds.coins.clone(),
                cat_coins: Vec::new(),
                nfts: Vec::new(),
                _pd: PhantomData,
            },
            fee,
        )
        .map_err(|e| TakeError::Build(e.to_string()))?;

        // Sign FIRST — the human is inside this call, and nothing irreversible has happened yet.
        let signed_taker = self
            .money
            .authorize_and_sign(unsigned.coin_spends, SpendOpClass::Undeclared)
            .await?;

        let settlement = dig_offers::take_combine(unsigned.offer, signed_taker);
        let bundle_name = hex::encode(settlement.name());

        match self.publisher.push_detailed(&settlement) {
            Ok(PushOutcome::Accepted | PushOutcome::AlreadyInMempool) => {
                Ok(TakenOffer { bundle_name })
            }
            Ok(PushOutcome::Rejected { reason }) => Err(TakeError::Rejected { reason }),
            Err(failure) if failure.may_have_reached_a_mempool() => {
                Err(TakeError::PushUnanswered {
                    detail: failure.to_string(),
                })
            }
            Err(failure) => Err(TakeError::PushNotSent(failure)),
        }
    }
}

/// How far the one in-flight take has got, as the Wallet pane should draw it.
///
/// The four states are the four `professional-ui` async states, and none of them claims a settled
/// swap: [`Broadcast`](Self::Broadcast) says a node accepted the bundle, which is a statement about a
/// node.
///
/// Whether the swap happened is a chain read, and **nothing in this app performs it for a take**
/// today — a take creates no `InFlightSend`, so the settlement read an ordinary send gets never
/// runs (dig_ecosystem#3111). This enum deliberately has no variant that could be mistaken for a
/// settled swap, which is what keeps the surface honest while that gap is open.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TakeProgress {
    /// Nothing is being taken.
    #[default]
    Idle,
    /// A take is building, waiting on the person's confirmation, or being pushed.
    Working,
    /// A node accepted the settlement bundle. NOT a settled swap.
    Broadcast {
        /// The spend-bundle name, lowercase hex — the handle to look the swap up by.
        bundle_name: String,
    },
    /// The take did not complete, in the words the failure itself used.
    Failed {
        /// What stopped it.
        why: String,
    },
}

/// The process-wide take holder: one take at a time, and the gate it runs through.
///
/// # Why it holds its own gate rather than sharing the send path's
///
/// A [`PolicyAuthorizer`](dig_account::PolicyAuthorizer) owns the rolling-period-cap ledger, and a
/// host that built one per request would turn a period cap into N per-transaction limits. That is
/// why the send path holds ONE gate per unlock, and the same reasoning would argue for one gate
/// across both paths.
///
/// It does not apply here, and the reason is specific rather than convenient: a take is authorized as
/// [`SpendOpClass::Undeclared`], which can never auto-approve, so it never reaches the cap ledger to
/// charge it or to be judged by it. A take therefore neither consumes an allowance nor benefits from
/// one, and a separate gate cannot launder a spend past a bound that was never consulted. Sharing the
/// send path's gate would instead mean reaching into `wallet::sending`'s private state from here.
///
/// If a take ever becomes auto-approvable, this reasoning expires and the two paths must share one
/// gate. That is stated here because the change would be silent otherwise.
#[derive(Default)]
pub struct TakeHolder {
    gate: std::sync::Mutex<Option<UnlockGate>>,
    progress: std::sync::Mutex<TakeProgress>,
}

/// The money gate built for one unlock, remembered against the address it rules on.
struct UnlockGate {
    address: String,
    money: std::sync::Arc<MoneyPath<HarnessAuthProvider<PromptedCeremony>>>,
    /// Where this take writes the story the confirm prompt tells (dig_ecosystem#3109). The gate is
    /// built once per unlock and the narrative differs per offer, so it is staged per operation
    /// rather than baked into the ceremony.
    narrative: NarrativeSlot,
}

/// The process-wide take holder.
pub fn holder() -> &'static TakeHolder {
    static HOLDER: std::sync::OnceLock<TakeHolder> = std::sync::OnceLock::new();
    HOLDER.get_or_init(TakeHolder::default)
}

/// What the Wallet pane should draw about the take in flight.
#[must_use]
pub fn progress() -> TakeProgress {
    holder().progress()
}

impl TakeHolder {
    /// What the take in flight is doing.
    #[must_use]
    pub fn progress(&self) -> TakeProgress {
        self.lock().clone()
    }

    /// Put the surface back to rest after a person has read a finished take's outcome.
    ///
    /// The one way out of both terminal states, so neither becomes furniture that cannot be
    /// dismissed (`professional-ui`: never trap the user).
    pub fn dismiss(&self) {
        *self.lock() = TakeProgress::Idle;
    }

    /// Take `reviewed`: read the wallet's coins, build, gate, sign, combine and push.
    ///
    /// # Why the shell's arm for this is one call
    ///
    /// Everything here is a decision — is there an account, is there a node, what did the failure
    /// mean — and the tray binary can execute none of it under test. So the binary's
    /// `TrayAction::TakeOffer` arm calls this and nothing else.
    ///
    /// It BLOCKS for as long as the person takes to confirm, so the caller must be a worker thread
    /// and never the repaint loop.
    pub fn take(
        &self,
        status: &crate::agent::SharedStatus,
        residency: Option<&AccountResidency>,
        reviewed: &ReviewedOffer,
    ) {
        if !self.begin() {
            return;
        }
        // Every broadcast this app makes raises the ONE centralized progress modal
        // (dig_ecosystem#3075); a take used to be the exception, which is dig_ecosystem#3110.
        let feed = Feed::app();
        let opening = Transaction::starting("Taking an offer", None);
        feed.publish(opening.clone());

        *self.lock() = match self.perform(status, residency, reviewed, &feed, &opening) {
            Ok(taken) => {
                feed.publish(opening.at(Stage::Pushed {
                    id: taken.bundle_name.clone(),
                }));
                TakeProgress::Broadcast {
                    bundle_name: taken.bundle_name,
                }
            }
            Err(error) => {
                let why = error.to_string();
                feed.publish(opening.at(Stage::Failed {
                    why: why.clone(),
                    next: NEXT_AFTER_A_FAILED_TAKE.to_string(),
                }));
                TakeProgress::Failed { why }
            }
        };
    }

    /// Claim the one take slot, or report that another take already holds it.
    ///
    /// Structural, not advisory: a second take of the same offer while the first is settling would
    /// spend the taker's coins twice against one maker half, and the second can only fail — after a
    /// person has confirmed it.
    fn begin(&self) -> bool {
        let mut progress = self.lock();
        if *progress == TakeProgress::Working {
            return false;
        }
        *progress = TakeProgress::Working;
        true
    }

    /// Read, build, gate, sign and push — every step that can fail, and none that record state.
    fn perform(
        &self,
        status: &crate::agent::SharedStatus,
        residency: Option<&AccountResidency>,
        reviewed: &ReviewedOffer,
        feed: &Feed,
        opening: &Transaction,
    ) -> Result<TakenOffer, TakeError> {
        let residency = residency.ok_or(TakeError::Locked)?;

        // Cloned out from under the lock, which is then released: the confirm ceremony below can
        // take minutes, and holding the status guard across it would stall the agent's own tick.
        let engine = match status.read() {
            Ok(status) => status.engine.clone(),
            Err(_) => crate::engine::EngineState::initial(),
        };
        let crate::engine::EngineState::Connected { endpoint, .. } = &engine else {
            return Err(TakeError::NoNode);
        };

        let (puzzle_hash, _) = residency.taker_identity().ok_or(TakeError::Locked)?;
        let chain = crate::chain::ControlChainSource::new(endpoint);
        let funds = SpendableXch::read_from(&chain, puzzle_hash)?;

        let custody = CustodyPolicy::Hot(HotWallet { auto_send_limit: 0 });
        let held = self.gate_for(residency, custody)?;
        let gate = held
            .as_ref()
            .expect("gate_for leaves a gate in place or returns an error");
        let money = &gate.money;

        // Both legs of the swap reach the confirm prompt, which the re-derived summary alone cannot
        // show (dig_ecosystem#3109). Held across the take and dropped with it, so no later spend
        // inherits this offer's story.
        let _telling = gate.narrative.set(reviewed.terms().narrative(
            copy::TAKE_HEADLINE,
            Some(copy::TAKE_CAUTION.to_string()),
        ));
        let publisher = crate::chain::ControlSpendPublisher::new(endpoint);

        feed.publish(opening.at(Stage::Signing));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| TakeError::Build(format!("this app could not start a worker: {e}")))?;
        runtime.block_on(
            TakeSession::new(residency, money, custody, &publisher).take(reviewed, &funds, 0),
        )
    }

    /// The money gate for this unlock, built once and reused — see the type docs for why it is not
    /// shared with the send path's.
    fn gate_for(
        &self,
        residency: &AccountResidency,
        custody: CustodyPolicy,
    ) -> Result<std::sync::MutexGuard<'_, Option<UnlockGate>>, TakeError> {
        let Some(Ok(address)) = residency.receiving_address() else {
            return Err(TakeError::Locked);
        };

        let mut held = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if !held.as_ref().is_some_and(|gate| gate.address == address) {
            let ceremony = PromptedCeremony::unlocking("confirm this swap");
            let narrative = ceremony.narrative();
            let money = MoneyPath::new(
                residency.clone(),
                HarnessAuthProvider::new(ceremony),
                dig_account::AccountId::new(crate::account::boot::DEFAULT_ACCOUNT_ID),
                dig_wallet_backend::types::Network::Mainnet,
                custody,
                dig_account::AutoSendPolicy::default(),
                std::sync::Arc::new(dig_account::SystemClock),
            )
            .map_err(|_| TakeError::Locked)?;
            *held = Some(UnlockGate {
                address,
                money: std::sync::Arc::new(money),
                narrative,
            });
        }
        Ok(held)
    }

    /// Take the progress lock, recovering from a poisoned one.
    ///
    /// A poisoned lock means an earlier take panicked. Refusing every later take — leaving a person
    /// with a wallet that has silently stopped working — is the worse answer, and it is the call the
    /// send path's own lock makes.
    fn lock(&self) -> std::sync::MutexGuard<'_, TakeProgress> {
        self.progress
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// What a person can do after a take did not go through.
///
/// [`Stage::Failed`] refuses a blank `next`, and the honest step after most take failures is to look
/// again rather than to retry: an offer somebody else has already taken will never become takeable.
const NEXT_AFTER_A_FAILED_TAKE: &str =
    "Check the offer is still open before trying again — somebody else may have taken it.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::auth::{AuthCeremony, CeremonyError, HarnessAuthProvider};
    use crate::wallet::offer_fixture::{
        an_offer_of, taker_spends_for, XCH_FOR_XCH, XCH_FOR_XCH_COST,
    };
    use async_trait::async_trait;
    use chia_protocol::{Bytes32, SpendBundle};
    use dig_account::{
        AccountId, AuthFactors, AutoSendPolicy, HotWallet, ProfileIx, SpendDecision, SpendSummary,
        SystemClock, Vault,
    };
    use dig_wallet_backend::types::Network;
    use std::sync::{Arc, Mutex};

    /// A publisher that records what it was handed, so a test inspects the BROADCAST bytes rather
    /// than bytes it constructed itself.
    #[derive(Default)]
    struct RecordingPublisher {
        pushed: Mutex<Vec<SpendBundle>>,
    }

    impl DetailedSpendPublisher for RecordingPublisher {
        fn push_detailed(&self, bundle: &SpendBundle) -> Result<PushOutcome, PublishFailure> {
            self.pushed.lock().unwrap().push(bundle.clone());
            Ok(PushOutcome::Accepted)
        }
    }

    /// A ceremony that answers every confirmation the same way, and records that it was asked.
    struct ScriptedCeremony {
        decision: SpendDecision,
        asked: Arc<Mutex<Vec<SpendSummary>>>,
    }

    #[async_trait]
    impl AuthCeremony for ScriptedCeremony {
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
            summary: &SpendSummary,
        ) -> Result<SpendDecision, CeremonyError> {
            self.asked.lock().unwrap().push(summary.clone());
            Ok(self.decision.clone())
        }
    }

    /// An unlocked account, its real custody gate, and a ceremony whose answer the test chooses.
    struct Bench {
        residency: AccountResidency,
        money: MoneyPath<HarnessAuthProvider<ScriptedCeremony>>,
        asked: Arc<Mutex<Vec<SpendSummary>>>,
        publisher: RecordingPublisher,
    }

    impl Bench {
        fn with_ceremony_answering(decision: SpendDecision) -> Self {
            let asked = Arc::new(Mutex::new(Vec::new()));
            let residency = crate::account::residency::test_support::residency();
            let money = MoneyPath::new(
                residency.clone(),
                HarnessAuthProvider::new(ScriptedCeremony {
                    decision,
                    asked: asked.clone(),
                }),
                AccountId::new("take-test"),
                Network::Mainnet,
                CustodyPolicy::Hot(HotWallet::default()),
                AutoSendPolicy::default(),
                Arc::new(SystemClock),
            )
            .expect("an unlocked residency yields a money path");
            Self {
                residency,
                money,
                asked,
                publisher: RecordingPublisher::default(),
            }
        }

        fn approving() -> Self {
            Self::with_ceremony_answering(SpendDecision::Approve)
        }

        /// Coins at the puzzle hash THIS account actually spends from — a take built against the
        /// same identity that will sign it is the only configuration that can reach a signature.
        fn funds_of(&self, amount: u64) -> SpendableXch {
            let (puzzle_hash, _) = self
                .residency
                .taker_identity()
                .expect("a fresh residency is unlocked");
            SpendableXch {
                coins: vec![Coin::new(Bytes32::new([0xB2; 32]), puzzle_hash, amount)],
            }
        }

        fn session(
            &self,
            custody: CustodyPolicy,
        ) -> TakeSession<'_, RecordingPublisher, HarnessAuthProvider<ScriptedCeremony>> {
            TakeSession::new(&self.residency, &self.money, custody, &self.publisher)
        }

        fn broadcasts(&self) -> Vec<SpendBundle> {
            self.publisher.pushed.lock().unwrap().clone()
        }

        fn confirmations_asked(&self) -> usize {
            self.asked.lock().unwrap().len()
        }
    }

    fn an_offer() -> ReviewedOffer {
        ReviewedOffer::read(&an_offer_of(XCH_FOR_XCH)).expect("the fixture offer reads")
    }

    /// **A take reaches a real signature, and BOTH halves of the swap are what reach the node.**
    ///
    /// This is the end-to-end acceptance for slice O2. The assertion is on the bundle the publisher
    /// was HANDED rather than on the return value, because a version that signed only the taker's
    /// half and pushed that would return `Ok` identically — and would settle nothing, since the
    /// maker's offered coins would never be spent.
    ///
    /// The discriminating property is coin-spend COUNT: the broadcast bundle must carry strictly
    /// more spends than `take_build` produced, which is true only if the maker's already-signed half
    /// was welded on. "A bundle was pushed" cannot see that, and a fixed expected number would pin
    /// the crate's internal spend layout rather than the property under test.
    #[tokio::test]
    async fn a_take_is_signed_and_the_combined_settlement_is_what_reaches_the_node() {
        let bench = Bench::approving();
        let offer = an_offer();
        let taker_half = taker_spends_for(offer.offer()).len();

        let taken = bench
            .session(CustodyPolicy::Hot(HotWallet::default()))
            .take(&offer, &bench.funds_of(2_000), 0)
            .await
            .expect("an approved take must reach a signature and a push");

        let broadcasts = bench.broadcasts();
        let [settlement] = broadcasts.as_slice() else {
            panic!("exactly one settlement bundle must be broadcast: {broadcasts:?}");
        };
        assert!(
            settlement.coin_spends.len() > taker_half,
            "the maker's half must be welded on: {} spends broadcast against {taker_half} built",
            settlement.coin_spends.len()
        );
        assert_eq!(
            taken.bundle_name,
            hex::encode(settlement.name()),
            "the handle returned must name the bundle actually broadcast"
        );
        assert_eq!(
            bench.confirmations_asked(),
            1,
            "an irreversible swap must be confirmed by the human, exactly once"
        );
    }

    /// **A declined confirmation signs nothing and broadcasts nothing.**
    ///
    /// The approving test above proves this path CAN reach a push, so a green here cannot be the
    /// flow silently failing earlier — together they separate "declined" from "never got there".
    #[tokio::test]
    async fn a_declined_confirmation_broadcasts_nothing() {
        let bench = Bench::with_ceremony_answering(SpendDecision::Decline(None));

        let err = bench
            .session(CustodyPolicy::Hot(HotWallet::default()))
            .take(&an_offer(), &bench.funds_of(2_000), 0)
            .await
            .expect_err("a declined swap must not settle");

        assert!(
            matches!(err, TakeError::Sign(MoneyPathError::Declined(_))),
            "{err}"
        );
        assert!(bench.broadcasts().is_empty());
    }

    /// **A vault profile is turned away BEFORE anything is built, signed or confirmed.**
    ///
    /// "Returns an error" is satisfied by a version that builds and signs first and fails at the
    /// gate, which would put the refusal in front of a person who had already agreed. So the
    /// ceremony's own record is asserted empty alongside the publisher's.
    #[tokio::test]
    async fn a_vault_profile_is_turned_away_before_a_spend_is_built() {
        let bench = Bench::approving();

        let err = bench
            .session(CustodyPolicy::Vault(Vault::default()))
            .take(&an_offer(), &bench.funds_of(2_000), 0)
            .await
            .expect_err("a vault profile may not take an offer");

        assert!(
            matches!(err, TakeError::Offer(OfferError::CustodyForbids(_))),
            "the refusal must be the custody one, named: {err}"
        );
        assert_eq!(
            bench.confirmations_asked(),
            0,
            "nobody may be asked to confirm a take that was never permitted"
        );
        assert!(bench.broadcasts().is_empty());
    }

    /// **A wallet that cannot cover the request is told the shortfall, and nobody is asked.**
    ///
    /// Taking the fixture costs 600 mojos and this wallet holds 100 — the refusal must name the
    /// figure, not merely fail, because "you cannot take this" with no number sends a person looking
    /// for the wrong remedy.
    #[tokio::test]
    async fn an_underfunded_wallet_is_told_what_it_is_short() {
        let bench = Bench::approving();

        let err = bench
            .session(CustodyPolicy::Hot(HotWallet::default()))
            .take(&an_offer(), &bench.funds_of(100), 0)
            .await
            .expect_err("a wallet short of the request cannot take");

        let TakeError::Build(why) = &err else {
            panic!("a shortfall is a build refusal, not a signing one: {err}");
        };
        assert!(
            why.contains("insufficient") && why.contains(&XCH_FOR_XCH_COST.to_string()),
            "the refusal must name what is needed: {why}"
        );
        assert_eq!(bench.confirmations_asked(), 0);
    }

    /// A chain that answers one puzzle hash with fixed records, or refuses every read.
    ///
    /// Hand-written rather than wrapping the canonical mock because the two properties under test —
    /// a refusal, and a list containing a SPENT coin — are exactly the two the mock's fixture chain
    /// is built never to produce.
    struct StubChain {
        records: Vec<dig_chainsource_interface::CoinRecord>,
        refuses: bool,
    }

    impl StubChain {
        fn holding(records: Vec<dig_chainsource_interface::CoinRecord>) -> Self {
            Self {
                records,
                refuses: false,
            }
        }

        fn that_cannot_answer() -> Self {
            Self {
                records: Vec::new(),
                refuses: true,
            }
        }
    }

    impl dig_chainsource_interface::ChainSource for StubChain {
        type Error = dig_chainsource_interface::ChainSourceError;

        fn coin_record(
            &self,
            _coin_id: Bytes32,
        ) -> Result<Option<dig_chainsource_interface::CoinRecord>, Self::Error> {
            Ok(None)
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<dig_chainsource_interface::CoinRecord>, Self::Error> {
            match self.refuses {
                true => Err(dig_chainsource_interface::ChainSourceError::Transport(
                    "the node did not answer".into(),
                )),
                false => Ok(self.records.clone()),
            }
        }

        fn coin_records_by_parent(
            &self,
            _parent_coin_id: Bytes32,
        ) -> Result<Vec<dig_chainsource_interface::CoinRecord>, Self::Error> {
            Ok(Vec::new())
        }

        fn coin_spend(
            &self,
            _coin_id: Bytes32,
        ) -> Result<Option<chia_protocol::CoinSpend>, Self::Error> {
            Ok(None)
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            Ok(Some(1))
        }

        fn resolve_singleton_lineage(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<dig_chainsource_interface::SingletonLineage>, Self::Error> {
            Ok(None)
        }

        fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
            Ok(None)
        }
    }

    fn record(amount: u64, spent_height: Option<u32>) -> dig_chainsource_interface::CoinRecord {
        dig_chainsource_interface::CoinRecord {
            coin: Coin::new(Bytes32::new([0x01; 32]), Bytes32::new([0x02; 32]), amount),
            confirmed_height: Some(1),
            spent_height,
            timestamp: None,
            coinbase: false,
        }
    }

    /// **A spent coin is not spendable, and an unspent one is.**
    ///
    /// Both are present in one answer, because a filter that dropped everything and a filter that
    /// dropped nothing each satisfy a single-coin fixture. The amounts differ so the surviving coin
    /// is identifiable rather than merely counted.
    #[test]
    fn a_spent_coin_is_not_offered_as_funding_and_an_unspent_one_is() {
        let chain = StubChain::holding(vec![record(700, Some(9)), record(1_300, None)]);

        let funds = SpendableXch::read_from(&chain, Bytes32::new([0x02; 32]))
            .expect("a chain that answered has stated what the wallet holds");

        assert_eq!(
            funds.coins.iter().map(|c| c.amount).collect::<Vec<_>>(),
            vec![1_300],
            "only the unspent coin may fund a take"
        );
    }

    /// **A chain that could not answer is NOT an empty wallet.**
    ///
    /// The nearest wrong version returns `Ok(SpendableXch::default())` on a read error, and every
    /// downstream assertion would still pass — until a funded person was told their swap was
    /// unaffordable. The test above supplies the honest control: the same call on a chain that DOES
    /// answer produces coins, so this refusal cannot be the reader simply never working.
    #[test]
    fn a_chain_that_could_not_answer_is_never_read_as_an_empty_wallet() {
        let err =
            SpendableXch::read_from(&StubChain::that_cannot_answer(), Bytes32::new([0x02; 32]))
                .expect_err("an unanswered read states nothing about the money");

        assert!(matches!(err, TakeError::FundsUnreadable(_)), "{err}");
    }

    /// **A second take is refused while one is in flight, and the first is left undisturbed.**
    ///
    /// The refusal is what stops a person confirming a swap whose coins are already committed to an
    /// identical one. Asserting the progress afterwards is what separates "refused" from "refused
    /// and quietly reset the state the first take is relying on".
    #[test]
    fn a_second_take_is_refused_while_one_is_in_flight() {
        let holder = TakeHolder::default();

        assert!(holder.begin(), "the first take claims the slot");
        assert!(!holder.begin(), "the second is refused");
        assert_eq!(holder.progress(), TakeProgress::Working);
    }

    /// **A finished take can always be dismissed**, so neither terminal state becomes furniture a
    /// person cannot clear (`professional-ui`: never trap the user).
    #[test]
    fn a_finished_take_can_be_dismissed_back_to_rest() {
        let holder = TakeHolder::default();
        *holder.lock() = TakeProgress::Failed {
            why: "something went wrong".into(),
        };

        holder.dismiss();

        assert_eq!(holder.progress(), TakeProgress::Idle);
    }
}
