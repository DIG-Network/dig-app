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
//! about a node and not about the chain; the settled verdict comes from a later chain read. And it
//! draws no progress: the centralized modal observes the transaction feed and is raised by ANY
//! broadcast, so a take inherits it with no opt-in.

use chia_protocol::Coin;
use chia_sdk_driver::SpendContext;
use dig_account::mint::PushOutcome;
use dig_account::{AuthProvider, CustodyPolicy, SpendOpClass};
use dig_offers::TakerFunds;
use indexmap::IndexMap;
use std::marker::PhantomData;

use crate::account::money::{MoneyPath, MoneyPathError};
use crate::account::residency::AccountResidency;
use crate::chain::{DetailedSpendPublisher, PublishFailure};
use crate::wallet::offer::{take_permitted_by, OfferError, ReviewedOffer};

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
}
