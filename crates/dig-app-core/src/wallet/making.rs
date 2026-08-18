//! Making an offer: commit what you give, state what you want, get a string to share
//! (dig_ecosystem#3077).
//!
//! # The order, and why it is this order
//!
//! 1. **refuse early** — a vault-tier profile cannot commit funds to the settlement puzzle, so it is
//!    turned away by [`make_permitted_by`] before a spend is built, exactly as a take is. The control
//!    is disabled with the reason attached rather than failing after a person has agreed.
//! 2. **build** — [`dig_offers::make_build`] spends the offered coins into settlement and ASSERTS the
//!    requested payments. The maker never funds the side it asked for; that is the taker's job.
//! 3. **sign** — [`MoneyPath::authorize_and_sign`](crate::account::money::MoneyPath::authorize_and_sign)
//!    rules on those bytes at the custody gate and, if the human agrees, signs. The key never leaves
//!    dig-account.
//! 4. **assemble** — [`dig_offers::make_assemble`] folds the signed half and the requested payments
//!    into the `offer1…` string, in the SAME [`SpendContext`] the build used.
//!
//! # A make does NOT broadcast, and that is the whole shape of it
//!
//! There is no push step and no progress modal, because nothing is sent. The maker's signed spend
//! lives inside the offer string and reaches a mempool only when somebody takes it. So the money is
//! *committed* — those coins are promised to this offer and spending them elsewhere would invalidate
//! it — while nothing has *moved*. [`MADE`](MakeProgress::Made) says exactly that and no more, and
//! [`crate::wallet::offer_words::MAKE_CAUTION`] says it to the person at the confirm gate, because it
//! is the asymmetry a make is most often misread in.
//!
//! # What can be offered, and why the shape is this narrow today
//!
//! The offered side is **XCH only**. A CAT-offered leg needs each funding coin's lineage proof, which
//! the app's coin read does not carry, and an NFT leg needs the NFT parsed in the build context. The
//! REQUESTED side has no such constraint — the maker only asserts it — so asking for XCH or for a CAT
//! (**$DIG** among them) works today. Offering a control that would fail at build time is the thing
//! this narrowness exists to avoid; the surface states the limit instead.

use chia_protocol::Bytes32;
use chia_sdk_driver::SpendContext;
use dig_account::{AuthProvider, CustodyPolicy, HotWallet, SpendOpClass};
use dig_offers::{OfferedSide, RequestedSide};
use indexmap::IndexMap;
use std::marker::PhantomData;

use crate::account::auth::HarnessAuthProvider;
use crate::account::ceremony::PromptedCeremony;
use crate::account::money::{MoneyPath, MoneyPathError};
use crate::account::narrative::{NarrativeSlot, TradeNarrative};
use crate::account::residency::AccountResidency;
use crate::wallet::offer::{OfferError, OfferLeg, VAULT_CANNOT_TAKE};
use crate::wallet::offer_words as copy;
use crate::wallet::taking::SpendableXch;

/// What the maker wants back — the requested side, as the form collects it.
///
/// XCH and CAT only. A requested NFT needs its `NftAssetInfo` to rebuild the settlement puzzle hash,
/// which is a chain read this app does not perform, so it is absent rather than half-supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted {
    /// Native XCH, in mojos.
    Xch {
        /// The amount asked for, in mojos.
        mojos: u64,
    },
    /// A CAT — **$DIG** among them — in the asset's own base units.
    Cat {
        /// The CAT's asset id (TAIL hash).
        asset_id: Bytes32,
        /// The amount asked for, in the asset's base units.
        amount: u64,
    },
}

impl Wanted {
    /// This side as the display leg the narrative and the card both phrase.
    #[must_use]
    fn leg(&self) -> OfferLeg {
        match self {
            Self::Xch { mojos } => OfferLeg::Xch { mojos: *mojos },
            Self::Cat { asset_id, amount } => OfferLeg::Cat {
                asset_id: hex::encode(asset_id),
                amount: *amount,
            },
        }
    }

    /// Whether this side asks for anything at all.
    fn is_zero(&self) -> bool {
        match self {
            Self::Xch { mojos } => *mojos == 0,
            Self::Cat { amount, .. } => *amount == 0,
        }
    }
}

/// A filled-in offer, before anything is built.
///
/// Both sides are required and both must be non-zero, which [`checked`](Self::checked) is the only
/// way to establish — so a [`MakeDraft`] that exists is one an offer can be built from, and the
/// surface's refusal and the builder's refusal cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeDraft {
    give_mojos: u64,
    want: Wanted,
}

impl MakeDraft {
    /// Check a filled-in form, or say which side is not yet an offer.
    ///
    /// The two zero cases are named separately because they are different fields on the form, and a
    /// single "fill this in" would point at neither.
    pub fn checked(give_mojos: u64, want: Wanted) -> Result<Self, MakeError> {
        if give_mojos == 0 {
            return Err(MakeError::NothingOffered);
        }
        if want.is_zero() {
            return Err(MakeError::NothingRequested);
        }
        Ok(Self { give_mojos, want })
    }

    /// The XCH this offer commits, in mojos.
    #[must_use]
    pub fn give_mojos(&self) -> u64 {
        self.give_mojos
    }

    /// What the offer asks a taker to pay.
    #[must_use]
    pub fn want(&self) -> &Wanted {
        &self.want
    }

    /// The story the confirm prompt tells about this make (dig_ecosystem#3109).
    ///
    /// Both sides are named from the MAKER's point of view — the direction they filled the form in —
    /// so the sentence at the custody gate and the sentence on the card describe one act. The caution
    /// is what no figure on either screen can express: the given side is committed now, and the asked
    /// side may never arrive.
    #[must_use]
    pub fn narrative(&self) -> TradeNarrative {
        TradeNarrative {
            headline: copy::MAKE_HEADLINE.to_string(),
            you_give: vec![OfferLeg::Xch {
                mojos: self.give_mojos,
            }
            .phrase()],
            you_receive: vec![self.want.leg().phrase()],
            caution: Some(copy::MAKE_CAUTION.to_string()),
        }
    }
}

/// A make that did not complete, named by WHICH step stopped it.
#[derive(Debug, thiserror::Error)]
pub enum MakeError {
    /// The form offers nothing. An offer with no offered side is not an offer.
    #[error("choose how much XCH this offer gives before making it")]
    NothingOffered,

    /// The form asks for nothing — which would be a gift to whoever finds the string first.
    #[error("choose what you want in return before making this offer")]
    NothingRequested,

    /// The account is locked, so nothing could be built or signed. Fail-closed.
    #[error("the account is locked — no offer was made")]
    Locked,

    /// No node is connected, so the wallet's coins could not be read.
    #[error("no DIG node is connected, so this app cannot see the coins to offer")]
    NoNode,

    /// A node is connected and could not answer what this wallet holds.
    ///
    /// Never collapsed into an empty coin list: a read that failed has made no claim about the money,
    /// and telling a funded person they have nothing to offer is the lie this wallet refuses.
    #[error("this app could not read what your wallet holds: {0}")]
    FundsUnreadable(String),

    /// This profile's custody policy forbids committing funds to the settlement puzzle.
    #[error(transparent)]
    Custody(#[from] OfferError),

    /// The maker's half could not be built — most often because the wallet cannot cover what is being
    /// offered. `dig-offers` names the shortfall, and that text is carried through verbatim.
    #[error("this offer could not be built: {0}")]
    Build(String),

    /// The custody gate refused, or the person declined the confirmation. Nothing was signed.
    #[error(transparent)]
    Sign(#[from] MoneyPathError),

    /// Signed, and then the offer string could not be encoded.
    ///
    /// Its own variant because it is the one failure that leaves a SIGNED maker half with no offer to
    /// show for it. Nothing was broadcast and nothing can settle — the coins remain spendable — but
    /// the person must be told the attempt got that far rather than reading a generic build failure.
    #[error("the offer was signed but could not be encoded, so there is nothing to share: {0}")]
    Assemble(String),
}

/// An `offer1…` string this wallet just made, and the terms it was made from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "an offer nobody is shown is an offer nobody can take"]
pub struct MadeOffer {
    /// The `offer1…` string, to share verbatim.
    pub offer: String,
}

/// Build, gate, sign and assemble one offer.
///
/// One make at a time is structural: [`make`](Self::make) consumes the session, as the send and take
/// sessions do, so a caller holding a [`MadeOffer`] has no session left to make a second offer from
/// the same coins with.
pub struct MakeSession<'a, P>
where
    P: AuthProvider,
{
    residency: &'a AccountResidency,
    money: &'a MoneyPath<P>,
    custody: CustodyPolicy,
}

impl<'a, P> MakeSession<'a, P>
where
    P: AuthProvider,
{
    /// Assemble a session over the live account and its money gate.
    ///
    /// There is no publisher argument, and its absence is the point: a make has nothing to broadcast.
    pub fn new(
        residency: &'a AccountResidency,
        money: &'a MoneyPath<P>,
        custody: CustodyPolicy,
    ) -> Self {
        Self {
            residency,
            money,
            custody,
        }
    }

    /// Make the offer `draft` describes, funding the offered side from `funds` and reserving `fee`.
    ///
    /// The op class is [`SpendOpClass::Undeclared`], which can never auto-approve, so every make
    /// reaches the confirm ceremony. A make commits an asset against a promise, and no configured
    /// mojo allowance can weigh that — the same reasoning that keeps a take unconditionally escalated.
    pub async fn make(
        self,
        draft: &MakeDraft,
        funds: &SpendableXch,
        fee: u64,
    ) -> Result<MadeOffer, MakeError> {
        make_permitted_by(&self.custody)?;
        let (change_puzzle_hash, public_key) =
            self.residency.taker_identity().ok_or(MakeError::Locked)?;

        let mut owner_keys = IndexMap::new();
        owner_keys.insert(change_puzzle_hash, public_key);

        // ONE context for build and assemble. `make_assemble` rebuilds the requested side from
        // allocator-relative pointers that exist only in the context that created them, so a second
        // context here would produce an offer describing a different requested leg.
        let mut ctx = SpendContext::new();
        let unsigned = dig_offers::make_build(
            &mut ctx,
            OfferedSide {
                change_puzzle_hash,
                owner_keys,
                xch_coins: funds.coins.clone(),
                cat_coins: Vec::new(),
                nfts: Vec::new(),
                offer_xch: draft.give_mojos(),
                offer_cats: Vec::new(),
                _pd: PhantomData,
            },
            requested_side(draft, change_puzzle_hash),
            fee,
        )
        .map_err(|e| MakeError::Build(e.to_string()))?;

        let signed = self
            .money
            .authorize_and_sign(unsigned.coin_spends, SpendOpClass::Undeclared)
            .await?;

        let offer = dig_offers::make_assemble(
            &mut ctx,
            signed,
            unsigned.requested_payments,
            unsigned.requested_asset_info,
        )
        .map_err(|e| MakeError::Assemble(e.to_string()))?;

        Ok(MadeOffer { offer })
    }
}

/// The requested side `draft` describes, paid to `payee`.
///
/// Extracted from [`MakeSession::make`] because it is the whole of the give/want mapping and the one
/// place a wrong version is invisible: an offer built with the two sides transposed encodes and
/// decodes perfectly and is takeable — it simply trades the opposite way from what the person asked
/// for. Pulling it out gives that mapping a test.
///
/// `payee` is the MAKER's own address: the maker is who the requested payment is made to.
pub(crate) fn requested_side(draft: &MakeDraft, payee: Bytes32) -> RequestedSide {
    let (xch, cats) = match draft.want() {
        Wanted::Xch { mojos } => (*mojos, Vec::new()),
        Wanted::Cat { asset_id, amount } => (0, vec![(*asset_id, *amount)]),
    };
    RequestedSide {
        payee_puzzle_hash: payee,
        xch,
        cats,
        nfts: Vec::new(),
    }
}

/// Whether a profile on `custody` may make an offer at all.
///
/// The same rule as taking, for the same reason and with the same words: making an offer spends the
/// offered coins into the settlement puzzle, which is a `ProtocolStructure` a vault-tier profile may
/// not pay. Checked before a spend is built so the control carries the reason.
pub fn make_permitted_by(custody: &CustodyPolicy) -> Result<(), OfferError> {
    match custody {
        CustodyPolicy::Hot(_) => Ok(()),
        CustodyPolicy::Vault(_) => Err(OfferError::CustodyForbids(VAULT_CANNOT_TAKE.to_string())),
    }
}

/// The draft the Wallet pane is currently showing, ready for the shell to make.
///
/// A [`MakeDraft`] cannot ride on a `Copy` [`TrayAction`](crate::tray_menu::TrayAction), and the
/// stronger reason is the one that would apply anyway: what must reach the shell is the draft a
/// person actually filled in and read back, and passing the raw figures separately would put a
/// second, unchecked copy in flight for the two to disagree about.
fn draft_slot() -> &'static std::sync::Mutex<Option<MakeDraft>> {
    static SLOT: std::sync::OnceLock<std::sync::Mutex<Option<MakeDraft>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(Default::default)
}

/// Remember `draft` as the offer on screen, replacing whatever was there.
pub fn stage(draft: Option<MakeDraft>) {
    if let Ok(mut slot) = draft_slot().lock() {
        *slot = draft;
    }
}

/// The draft on screen, if the form currently describes an offer.
#[must_use]
pub fn staged() -> Option<MakeDraft> {
    draft_slot().lock().ok().and_then(|slot| slot.clone())
}

/// How far the one in-flight make has got, as the Wallet pane draws it.
///
/// The three non-idle states are the `professional-ui` working / success / error states. The success
/// state is [`Made`](Self::Made) and it carries the offer string, because an offer nobody can copy is
/// an offer that was not really made.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum MakeProgress {
    /// Nothing is being made.
    #[default]
    Idle,
    /// An offer is building, or waiting on the person's confirmation.
    Working,
    /// The offer exists and is ready to share. Nothing has been broadcast.
    Made {
        /// The `offer1…` string, shown in full so it can be copied.
        offer: String,
    },
    /// The make did not complete, in the words the failure itself used.
    Failed {
        /// What stopped it.
        why: String,
    },
}

/// The process-wide make holder: one make at a time, and the gate it runs through.
#[derive(Default)]
pub struct MakeHolder {
    gate: std::sync::Mutex<Option<UnlockGate>>,
    progress: std::sync::Mutex<MakeProgress>,
}

/// The money gate built for one unlock, remembered against the address it rules on, together with the
/// slot each make stages its confirm-prompt story in.
struct UnlockGate {
    address: String,
    money: std::sync::Arc<MoneyPath<HarnessAuthProvider<PromptedCeremony>>>,
    narrative: NarrativeSlot,
}

/// The process-wide make holder.
pub fn holder() -> &'static MakeHolder {
    static HOLDER: std::sync::OnceLock<MakeHolder> = std::sync::OnceLock::new();
    HOLDER.get_or_init(MakeHolder::default)
}

/// What the Wallet pane should draw about the make in flight.
#[must_use]
pub fn progress() -> MakeProgress {
    holder().progress()
}

impl MakeHolder {
    /// What the make in flight is doing.
    #[must_use]
    pub fn progress(&self) -> MakeProgress {
        self.lock().clone()
    }

    /// Put the surface back to rest after a person has read a finished make's outcome.
    ///
    /// The one way out of both terminal states, so a made offer does not become furniture that cannot
    /// be dismissed (`professional-ui`: never trap the user).
    pub fn dismiss(&self) {
        *self.lock() = MakeProgress::Idle;
    }

    /// Make the offer `draft` describes: read the wallet's coins, build, gate, sign and assemble.
    ///
    /// BLOCKS for as long as the person takes to confirm, so the caller must be a worker thread and
    /// never the repaint loop.
    pub fn make(
        &self,
        status: &crate::agent::SharedStatus,
        residency: Option<&AccountResidency>,
        draft: &MakeDraft,
    ) {
        if !self.begin() {
            return;
        }
        *self.lock() = match self.perform(status, residency, draft) {
            Ok(made) => MakeProgress::Made { offer: made.offer },
            Err(error) => MakeProgress::Failed {
                why: error.to_string(),
            },
        };
    }

    /// Claim the one make slot, or report that another make already holds it.
    ///
    /// Structural rather than advisory: two makes built from one wallet's coins would select the same
    /// funding coins, so taking the second offer could only fail — after a person had confirmed it.
    fn begin(&self) -> bool {
        let mut progress = self.lock();
        if *progress == MakeProgress::Working {
            return false;
        }
        *progress = MakeProgress::Working;
        true
    }

    /// Read, build, gate, sign and assemble — every step that can fail, and none that record state.
    fn perform(
        &self,
        status: &crate::agent::SharedStatus,
        residency: Option<&AccountResidency>,
        draft: &MakeDraft,
    ) -> Result<MadeOffer, MakeError> {
        let residency = residency.ok_or(MakeError::Locked)?;

        // Cloned out from under the lock, which is then released: the confirm ceremony below can take
        // minutes, and holding the status guard across it would stall the agent's own tick.
        let engine = match status.read() {
            Ok(status) => status.engine.clone(),
            Err(_) => crate::engine::EngineState::initial(),
        };
        let crate::engine::EngineState::Connected { endpoint, .. } = &engine else {
            return Err(MakeError::NoNode);
        };

        let (puzzle_hash, _) = residency.taker_identity().ok_or(MakeError::Locked)?;
        let chain = crate::chain::ControlChainSource::new(endpoint);
        let funds = SpendableXch::read_from(&chain, puzzle_hash)
            .map_err(|e| MakeError::FundsUnreadable(e.to_string()))?;

        let custody = CustodyPolicy::Hot(HotWallet { auto_send_limit: 0 });
        let held = self.gate_for(residency, custody)?;
        let gate = held
            .as_ref()
            .expect("gate_for leaves a gate in place or returns an error");

        // Both sides of the trade reach the confirm prompt, which the re-derived summary alone cannot
        // show: a make pays the settlement puzzle and the requested side is an assertion, so without
        // this the prompt would describe a payment to a puzzle hash and nothing else
        // (dig_ecosystem#3109).
        let _telling = gate.narrative.set(draft.narrative());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| MakeError::Build(format!("this app could not start a worker: {e}")))?;
        runtime.block_on(MakeSession::new(residency, &gate.money, custody).make(draft, &funds, 0))
    }

    /// The money gate for this unlock, built once and reused.
    ///
    /// Its own gate rather than the send path's, for the reason the take holder records: a make is
    /// authorized as [`SpendOpClass::Undeclared`], which never reaches the rolling-period cap ledger
    /// to charge it or be judged by it, so a separate gate cannot launder a spend past a bound that
    /// was never consulted.
    fn gate_for(
        &self,
        residency: &AccountResidency,
        custody: CustodyPolicy,
    ) -> Result<std::sync::MutexGuard<'_, Option<UnlockGate>>, MakeError> {
        let Some(Ok(address)) = residency.receiving_address() else {
            return Err(MakeError::Locked);
        };

        let mut held = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if !held.as_ref().is_some_and(|gate| gate.address == address) {
            let ceremony = PromptedCeremony::unlocking("confirm this offer");
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
            .map_err(|_| MakeError::Locked)?;
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
    /// A poisoned lock means an earlier make panicked. Refusing every later make — leaving a person
    /// with a wallet that has silently stopped working — is the worse answer, and it is the call every
    /// other holder here makes.
    fn lock(&self) -> std::sync::MutexGuard<'_, MakeProgress> {
        self.progress
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_account::Vault;

    fn a_dig_asset_id() -> Bytes32 {
        dig_constants::DIG_ASSET_ID
    }

    /// **Both empty sides are refused, and they are refused DIFFERENTLY.**
    ///
    /// Two fields, two sentences: a single "fill this in" would point at neither, and a draft that
    /// accepted a zero on either side would build an offer that gives nothing or asks nothing. The
    /// valid case is asserted alongside, so a checker that refused everything also fails.
    #[test]
    fn a_draft_needs_something_on_both_sides_and_says_which_is_missing() {
        let want = Wanted::Xch { mojos: 1_000 };

        let nothing_offered = MakeDraft::checked(0, want.clone())
            .expect_err("an offer that gives nothing is not an offer");
        let nothing_wanted = MakeDraft::checked(500, Wanted::Xch { mojos: 0 })
            .expect_err("an offer that asks nothing is a gift to whoever finds it");

        assert!(matches!(nothing_offered, MakeError::NothingOffered));
        assert!(matches!(nothing_wanted, MakeError::NothingRequested));
        assert_ne!(nothing_offered.to_string(), nothing_wanted.to_string());

        assert!(MakeDraft::checked(500, want).is_ok());
    }

    /// **A zero-amount CAT request is refused too.**
    ///
    /// The nearest wrong version of [`Wanted::is_zero`] checks only the XCH arm — which is the arm the
    /// test above exercises — so this fixture varies the ASSET rather than the amount, and would pass
    /// under an implementation that let every CAT through.
    #[test]
    fn a_request_for_zero_of_a_token_is_refused_as_well() {
        let outcome = MakeDraft::checked(
            500,
            Wanted::Cat {
                asset_id: a_dig_asset_id(),
                amount: 0,
            },
        );
        assert!(matches!(outcome, Err(MakeError::NothingRequested)));
    }

    /// **The confirm-prompt story names what is committed AND what was asked for.**
    ///
    /// This is dig_ecosystem#3109 for the make path. The fixture asks for **$DIG** deliberately: a
    /// CAT leg is the case where the re-derived summary is most misleading, because the offered XCH is
    /// the only figure it can see and the token side is invisible to it. The two legs are different
    /// assets, so a narrative that printed one side twice fails rather than merely reading oddly.
    ///
    /// # Why the sides are asserted PER LINE
    ///
    /// Both figures appear in the body whichever line they land on, so `contains` over the whole body
    /// is an outcome assertion that cannot see placement — it stays green under a narrative that tells
    /// a maker they RECEIVE what they are committing. Each figure is therefore pinned to its own line,
    /// and the transposition is refuted a second time from the other direction.
    #[test]
    fn the_make_narrative_names_the_committed_side_and_the_asked_side() {
        let draft = MakeDraft::checked(
            5_000_000_000_000,
            Wanted::Cat {
                asset_id: a_dig_asset_id(),
                amount: 1_500,
            },
        )
        .expect("both sides are non-zero");

        let body = draft.narrative().render();

        let give_line = body
            .lines()
            .find(|line| line.starts_with("You give:"))
            .expect("the prompt names what leaves");
        let receive_line = body
            .lines()
            .find(|line| line.starts_with("You receive:"))
            .expect("the prompt names what arrives");

        assert!(
            give_line.contains("5 XCH"),
            "the COMMITTED side belongs on the give line: {body}"
        );
        assert!(
            receive_line.contains("1.5 $DIG"),
            "the ASKED side belongs on the receive line, which is the whole defect: {body}"
        );
        assert!(
            !receive_line.contains("5 XCH"),
            "a transposed narrative promises the maker what they are committing: {body}"
        );
        assert!(
            body.contains("only when somebody takes it"),
            "a make must say that the asked side may never arrive: {body}"
        );
    }

    /// **A vault profile may not make an offer, and is told the same thing it is told about taking.**
    ///
    /// One sentence for one rule: a vault profile that read two different explanations of the same
    /// hot-wallet-only outflow rule would reasonably conclude they were two different limits.
    #[test]
    fn a_vault_profile_is_refused_with_the_hot_wallet_remedy() {
        assert!(make_permitted_by(&CustodyPolicy::Hot(HotWallet::default())).is_ok());

        let err = make_permitted_by(&CustodyPolicy::Vault(Vault::default()))
            .expect_err("a vault profile cannot commit funds to the settlement puzzle");
        let OfferError::CustodyForbids(why) = err else {
            panic!("a vault refusal is a custody refusal");
        };
        assert_eq!(why, VAULT_CANNOT_TAKE);
    }

    /// **A second make is refused while one is in flight.**
    ///
    /// Two makes from one wallet select the same funding coins, so the second offer could only ever
    /// fail to be taken. The holder is driven through its real state transitions rather than asserted
    /// on a constructed value.
    #[test]
    fn one_make_at_a_time() {
        let holder = MakeHolder::default();

        assert!(holder.begin(), "the first make claims the slot");
        assert!(
            !holder.begin(),
            "the second is refused while the first runs"
        );

        holder.dismiss();
        assert!(holder.begin(), "and the slot is reusable once it is idle");
    }
}
