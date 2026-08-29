//! Cancelling an offer you made: reclaim the coins it holds, and make it unfillable
//! (dig_ecosystem#3077).
//!
//! # What cancelling actually is, because the mechanism explains every rule below
//!
//! An offered coin is spent into the settlement puzzle inside the offer bundle, but that spend only
//! settles when a taker fulfils it. To cancel, the maker spends the SAME still-unspent coins
//! somewhere else — a competing spend. The chain then contains one of the two, never both, so the
//! outstanding `offer1…` string becomes impossible to fill.
//!
//! Three consequences follow, and all three are user-visible:
//!
//! * **It is destructive and irreversible** (NC-14, dig_ecosystem#3079). There is no un-cancel; a
//!   person who wants the offer back must make a new one, with a new string.
//! * **It is a race.** If a taker's settlement reaches a mempool first, the cancel loses and the swap
//!   happens. So a cancel that a node accepted is not a cancelled offer — that is a chain read, and
//!   [`CancelProgress::Broadcast`] says only what it knows.
//! * **It looks like nothing.** The reclaim pays the maker's own address, so the re-derived confirm
//!   summary reads as an ordinary self-payment. The thing being destroyed appears in no figure on the
//!   screen, which is exactly why [`crate::wallet::offer_words::CANCEL_CAUTION`] exists.
//!
//! # The order
//!
//! 1. **build** — [`dig_offers::cancel_build`] reads the offer, finds its still-cancellable coins, and
//!    produces UNSIGNED reclaim spends.
//! 2. **sign** — the custody gate rules on those bytes and, if the human agrees, signs.
//! 3. **push** — the node broadcasts (§908: the node signs nothing), and the centralized progress
//!    modal is raised through [`crate::transaction::Feed`] like every other broadcast this app makes.

use dig_account::mint::PushOutcome;
use dig_account::{AuthProvider, CustodyPolicy, HotWallet, SpendOpClass};
use indexmap::IndexMap;

use crate::account::auth::HarnessAuthProvider;
use crate::account::ceremony::PromptedCeremony;
use crate::account::money::{MoneyPath, MoneyPathError};
use crate::account::narrative::{NarrativeSlot, TradeNarrative};
use crate::account::residency::AccountResidency;
use crate::chain::{DetailedSpendPublisher, PublishFailure};
use crate::transaction::{Feed, Stage, Transaction, Writing};
use crate::wallet::offer::ReviewedOffer;
use crate::wallet::offer_words as copy;
use chia_sdk_driver::SpendContext;

/// A cancel that did not complete, named by WHICH step stopped it.
///
/// [`PushUnanswered`](CancelError::PushUnanswered) is separated from every other failure for the
/// reason it always is: it is the only one that may yet have taken effect, so retrying it blind is
/// the action that can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum CancelError {
    /// The account is locked, so nothing could be built or signed. Fail-closed.
    #[error("the account is locked — the offer was not cancelled")]
    Locked,

    /// No node is connected, so nothing could be pushed.
    #[error("no DIG node is connected, so the cancellation could not be broadcast")]
    NoNode,

    /// The offer has no coins this wallet can reclaim.
    ///
    /// `dig-offers` names the reason — already settled, not this wallet's offer, or an offered leg
    /// that must be reclaimed through a CAT or NFT layer this builder does not construct — and that
    /// text is carried through verbatim rather than replaced with a guess.
    #[error("this offer cannot be cancelled from here: {0}")]
    Build(String),

    /// The custody gate refused, or the person declined the confirmation. Nothing was signed.
    #[error(transparent)]
    Sign(#[from] MoneyPathError),

    /// A mempool judged the reclaim and rejected it. The offer is still fillable.
    #[error("the network rejected the cancellation, so the offer is still live: {reason}")]
    Rejected {
        /// The mempool's own words.
        reason: String,
    },

    /// The push was never answered, so the reclaim MAY have reached a mempool.
    #[error(
        "the cancellation was sent and the node did not answer — check whether the offer's coins \
         moved before trying again: {detail}"
    )]
    PushUnanswered {
        /// What the transport reported.
        detail: String,
    },

    /// The push provably never left this machine, so the offer is untouched and it is safe to retry.
    #[error("the cancellation was not sent, and the offer is unchanged: {0}")]
    PushNotSent(#[source] PublishFailure),
}

/// A reclaim bundle a mempool has accepted, and the chain has not yet settled.
///
/// It carries no verdict. A cancel races any taker's settlement, so "accepted" is a statement about a
/// node and never about whether the offer is dead.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "an accepted push is not a cancelled offer; the chain decides that"]
pub struct CancelledOffer {
    /// The spend-bundle name (its hash, lowercase hex) — the handle to look the reclaim up by.
    pub bundle_name: String,
}

/// The story the confirm prompt tells about cancelling `reviewed` (dig_ecosystem#3109, NC-14).
///
/// # Why the sides are the way round they are
///
/// [`OfferTerms`](crate::wallet::offer::OfferTerms) is written from the TAKER's point of view — it
/// exists to let somebody decide whether to take an offer. The person cancelling is the MAKER, so
/// their side is the offer's `you_receive`: what this offer would have delivered to a taker is
/// exactly what the maker committed and is now reclaiming.
///
/// Reading it in the taker's direction is the nearest wrong version of this function, and it would
/// tell a person they are getting back the thing they were asking for — money they never had.
#[must_use]
pub fn cancel_narrative(reviewed: &ReviewedOffer) -> TradeNarrative {
    let reclaimed: Vec<String> = reviewed
        .terms()
        .you_receive
        .iter()
        .map(|leg| format!("{}{}", copy::CANCEL_RECLAIM_PREFIX, leg.phrase()))
        .collect();
    TradeNarrative {
        headline: copy::CANCEL_HEADLINE.to_string(),
        // Nothing leaves: the coins were already committed, and this takes them back. Stated as an
        // empty side rather than omitted, so the prompt keeps its shape across all three acts.
        you_give: Vec::new(),
        you_receive: reclaimed,
        caution: Some(copy::CANCEL_CAUTION.to_string()),
    }
}

/// Build, gate, sign and push one cancellation.
///
/// One cancel at a time is structural: [`cancel`](Self::cancel) consumes the session.
pub struct CancelSession<'a, Pub, P>
where
    Pub: DetailedSpendPublisher + ?Sized,
    P: AuthProvider,
{
    residency: &'a AccountResidency,
    money: &'a MoneyPath<P>,
    publisher: &'a Pub,
}

impl<'a, Pub, P> CancelSession<'a, Pub, P>
where
    Pub: DetailedSpendPublisher + ?Sized,
    P: AuthProvider,
{
    /// Assemble a session over the live account, its money gate, and the node's push seam.
    pub fn new(
        residency: &'a AccountResidency,
        money: &'a MoneyPath<P>,
        publisher: &'a Pub,
    ) -> Self {
        Self {
            residency,
            money,
            publisher,
        }
    }

    /// Cancel `reviewed`, reclaiming its coins to this wallet and reserving `fee` mojos.
    ///
    /// There is no custody pre-check, and its ABSENCE is deliberate rather than an omission: a cancel
    /// pays the maker's own address, which is precisely what the vault rule permits, so refusing a
    /// vault profile here would withhold the one action that gets its money back out of an offer.
    ///
    /// The op class is [`SpendOpClass::Undeclared`], which can never auto-approve. Destroying an
    /// outstanding offer is irreversible and no mojo allowance can weigh it.
    pub async fn cancel(
        self,
        reviewed: &ReviewedOffer,
        fee: u64,
    ) -> Result<CancelledOffer, CancelError> {
        let (reclaim_puzzle_hash, public_key) =
            self.residency.taker_identity().ok_or(CancelError::Locked)?;

        let mut owner_keys = IndexMap::new();
        owner_keys.insert(reclaim_puzzle_hash, public_key);

        let mut ctx = SpendContext::new();
        let unsigned = dig_offers::cancel_build(
            &mut ctx,
            reviewed.offer(),
            reclaim_puzzle_hash,
            &owner_keys,
            fee,
        )
        .map_err(|e| CancelError::Build(e.to_string()))?;

        // Sign FIRST — the human is inside this call, and nothing irreversible has happened yet.
        let signed = self
            .money
            .authorize_and_sign(unsigned.coin_spends, SpendOpClass::Undeclared)
            .await?;
        let bundle_name = hex::encode(signed.name());

        match self.publisher.push_detailed(&signed) {
            Ok(PushOutcome::Accepted | PushOutcome::AlreadyInMempool) => {
                Ok(CancelledOffer { bundle_name })
            }
            Ok(PushOutcome::Rejected { reason }) => Err(CancelError::Rejected { reason }),
            Err(failure) if failure.may_have_reached_a_mempool() => {
                Err(CancelError::PushUnanswered {
                    detail: failure.to_string(),
                })
            }
            Err(failure) => Err(CancelError::PushNotSent(failure)),
        }
    }
}

/// How far the one in-flight cancellation has got, as the Wallet pane draws it.
///
/// No variant claims a cancelled offer, because a cancel races any taker's settlement and this app
/// performs no chain read to learn who won.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CancelProgress {
    /// Nothing is being cancelled.
    #[default]
    Idle,
    /// A cancellation is building, waiting on the person's confirmation, or being pushed.
    Working,
    /// A node accepted the reclaim. NOT a cancelled offer.
    Broadcast {
        /// The spend-bundle name, lowercase hex — the handle to look the reclaim up by.
        bundle_name: String,
    },
    /// The cancellation did not complete, in the words the failure itself used.
    Failed {
        /// What stopped it.
        why: String,
    },
}

/// The process-wide cancel holder: one cancellation at a time, and the gate it runs through.
#[derive(Default)]
pub struct CancelHolder {
    gate: std::sync::Mutex<Option<UnlockGate>>,
    progress: std::sync::Mutex<CancelProgress>,
}

/// The money gate built for one unlock, remembered against the address it rules on, together with the
/// slot each cancellation stages its confirm-prompt story in.
struct UnlockGate {
    address: String,
    money: std::sync::Arc<MoneyPath<HarnessAuthProvider<PromptedCeremony>>>,
    narrative: NarrativeSlot,
}

/// The process-wide cancel holder.
pub fn holder() -> &'static CancelHolder {
    static HOLDER: std::sync::OnceLock<CancelHolder> = std::sync::OnceLock::new();
    HOLDER.get_or_init(CancelHolder::default)
}

/// What the Wallet pane should draw about the cancellation in flight.
#[must_use]
pub fn progress() -> CancelProgress {
    holder().progress()
}

impl CancelHolder {
    /// What the cancellation in flight is doing.
    #[must_use]
    pub fn progress(&self) -> CancelProgress {
        self.lock().clone()
    }

    /// Put the surface back to rest after a person has read a finished cancellation's outcome.
    pub fn dismiss(&self) {
        *self.lock() = CancelProgress::Idle;
    }

    /// Cancel `reviewed`: build, gate, sign and push, reporting progress to the app-wide feed.
    ///
    /// BLOCKS for as long as the person takes to confirm, so the caller must be a worker thread and
    /// never the repaint loop.
    pub fn cancel(
        &self,
        status: &crate::agent::SharedStatus,
        residency: Option<&AccountResidency>,
        reviewed: &ReviewedOffer,
    ) {
        if !self.begin() {
            return;
        }
        let opening = Transaction::starting("Cancelling an offer", None);
        // The feed is CLAIMED, and a refusal is a refusal to spend (dig_ecosystem#3004). The slot
        // above excludes another CANCEL only; this excludes every other ceremony sharing the one
        // progress surface, which a reclaim would otherwise overwrite mid-flight.
        let Some(feed) = Feed::app().begin(opening.clone()) else {
            *self.lock() = CancelProgress::Failed {
                why: ANOTHER_WRITE_IS_IN_FLIGHT.to_string(),
            };
            return;
        };

        *self.lock() = match self.perform(status, residency, reviewed, &feed, &opening) {
            Ok(cancelled) => {
                feed.publish(opening.at(Stage::Pushed {
                    id: cancelled.bundle_name.clone(),
                }));
                CancelProgress::Broadcast {
                    bundle_name: cancelled.bundle_name,
                }
            }
            Err(error) => {
                let why = error.to_string();
                feed.publish(opening.at(Stage::Failed {
                    why: why.clone(),
                    next: NEXT_AFTER_A_FAILED_CANCEL.to_string(),
                }));
                CancelProgress::Failed { why }
            }
        };
    }

    /// Claim the one cancel slot, or report that another cancellation already holds it.
    fn begin(&self) -> bool {
        let mut progress = self.lock();
        if *progress == CancelProgress::Working {
            return false;
        }
        *progress = CancelProgress::Working;
        true
    }

    /// Build, gate, sign and push — every step that can fail.
    fn perform(
        &self,
        status: &crate::agent::SharedStatus,
        residency: Option<&AccountResidency>,
        reviewed: &ReviewedOffer,
        feed: &Writing,
        opening: &Transaction,
    ) -> Result<CancelledOffer, CancelError> {
        let residency = residency.ok_or(CancelError::Locked)?;

        // Cloned out from under the lock, which is then released: the confirm ceremony below can take
        // minutes, and holding the status guard across it would stall the agent's own tick.
        let engine = match status.read() {
            Ok(status) => status.engine.clone(),
            Err(_) => crate::engine::EngineState::initial(),
        };
        let crate::engine::EngineState::Connected { endpoint, .. } = &engine else {
            return Err(CancelError::NoNode);
        };

        let custody = CustodyPolicy::Hot(HotWallet { auto_send_limit: 0 });
        let held = self.gate_for(residency, custody)?;
        let gate = held
            .as_ref()
            .expect("gate_for leaves a gate in place or returns an error");

        // NC-14: the reclaim pays this wallet's own address, so the re-derived summary reads as a
        // self-payment and the destroyed offer appears in no figure on the screen.
        let _telling = gate.narrative.set(cancel_narrative(reviewed));
        feed.publish(opening.at(Stage::Signing));

        let publisher = crate::chain::ControlSpendPublisher::new(endpoint);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| CancelError::Build(format!("this app could not start a worker: {e}")))?;
        runtime.block_on(CancelSession::new(residency, &gate.money, &publisher).cancel(reviewed, 0))
    }

    /// The money gate for this unlock, built once and reused — see [`crate::wallet::taking`]'s
    /// `TakeHolder` for why an `Undeclared` operation does not share the send path's gate.
    fn gate_for(
        &self,
        residency: &AccountResidency,
        custody: CustodyPolicy,
    ) -> Result<std::sync::MutexGuard<'_, Option<UnlockGate>>, CancelError> {
        let Some(Ok(address)) = residency.receiving_address() else {
            return Err(CancelError::Locked);
        };

        let mut held = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if !held.as_ref().is_some_and(|gate| gate.address == address) {
            let ceremony = PromptedCeremony::unlocking("confirm this cancellation");
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
            .map_err(|_| CancelError::Locked)?;
            *held = Some(UnlockGate {
                address,
                money: std::sync::Arc::new(money),
                narrative,
            });
        }
        Ok(held)
    }

    /// Take the progress lock, recovering from a poisoned one.
    fn lock(&self) -> std::sync::MutexGuard<'_, CancelProgress> {
        self.progress
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// What a person is told when the app is already writing to the blockchain.
///
/// It must never imply the cancellation was attempted: the offer is still open, and a person who
/// believed otherwise would stop watching for it to be taken (dig_ecosystem#3004).
const ANOTHER_WRITE_IS_IN_FLIGHT: &str =
    "DIG is already writing to the blockchain. Nothing was sent, and the offer is still open — \
     wait for the write in progress to finish, then cancel it again.";

/// What a person can do after a cancellation did not go through.
///
/// [`Stage::Failed`] requires a next step and refuses to be a dead end, and the honest one here is
/// that the offer survived: it is still out there and still fillable.
const NEXT_AFTER_A_FAILED_CANCEL: &str =
    "The offer is still live and can still be taken. Try cancelling again, or leave it in place.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::offer_fixture::{an_offer_of, XCH_FOR_XCH};

    fn reviewed() -> ReviewedOffer {
        ReviewedOffer::read(&an_offer_of(XCH_FOR_XCH)).expect("the fixture offer reads")
    }

    /// **The maker gets back what the offer OFFERED, not what it asked for.**
    ///
    /// The fixture offers 400 mojos and requests 1,000 — two different figures on purpose, because
    /// reading the terms in the taker's direction is the nearest wrong version of this function and a
    /// symmetric fixture could not tell the two apart. Reading it the wrong way round would promise a
    /// person 1,000 mojos back: money they never committed and will not receive.
    #[test]
    fn a_cancellation_reclaims_the_offered_side_and_not_the_requested_one() {
        let body = cancel_narrative(&reviewed()).render();

        assert!(
            body.contains("0.0000000004 XCH"),
            "the reclaimed figure must be the OFFERED 400 mojos: {body}"
        );
        assert!(
            !body.contains("0.000000001 XCH"),
            "the requested 1,000 mojos are not reclaimed and must not be promised: {body}"
        );
    }

    /// **A cancellation is NAMED as destructive, and says what it destroys** (NC-14,
    /// dig_ecosystem#3079).
    ///
    /// A value delta is not consent. The reclaim pays the maker's own address, so every figure on the
    /// prompt is a self-payment; the thing being destroyed — an outstanding offer somebody may be
    /// about to accept — is present in no number at all. Both halves are asserted: that it cannot be
    /// undone, and that the shared string stops working.
    #[test]
    fn a_cancellation_names_itself_as_destructive_rather_than_showing_only_a_reclaim() {
        let body = cancel_narrative(&reviewed()).render();

        assert!(
            body.contains("cannot be undone"),
            "the irreversibility must be stated: {body}"
        );
        assert!(
            body.contains("stops working"),
            "what is destroyed must be named, not implied by a figure: {body}"
        );
    }

    /// **Nothing leaves, and the prompt says so rather than dropping the heading.**
    ///
    /// A cancel is the one operation of the three with an empty give side, and a renderer that
    /// omitted an empty side would give this act a different shape from a make and a take on the same
    /// screen.
    #[test]
    fn a_cancellation_states_that_nothing_leaves() {
        assert!(cancel_narrative(&reviewed())
            .render()
            .contains("You give: Nothing"));
    }

    /// **A second cancellation is refused while one is in flight.**
    #[test]
    fn one_cancellation_at_a_time() {
        let holder = CancelHolder::default();

        assert!(holder.begin(), "the first cancellation claims the slot");
        assert!(
            !holder.begin(),
            "the second is refused while the first runs"
        );

        holder.dismiss();
        assert!(holder.begin(), "and the slot is reusable once it is idle");
    }

    /// **A failed cancellation offers a way forward, and it is the TRUE one.**
    ///
    /// [`Stage::Failed`] refuses a blank `next`, but a filled-in dead end would satisfy the type while
    /// still leaving a person stuck. The sentence asserted here is the fact that actually matters
    /// after a failed cancel: the offer survived it.
    #[test]
    fn a_failed_cancellation_says_the_offer_is_still_live() {
        assert!(NEXT_AFTER_A_FAILED_CANCEL.contains("still live"));
    }
}
