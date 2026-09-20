//! The reward-distributor MINT seam (dig_ecosystem#3253) -- wired live as of dig-account 0.29.0.
//!
//! # This mirrors `account::profile_mint`'s shape, deliberately
//!
//! [`DistributorMintDoor`] and [`DistributorMintAvailability`] follow
//! `crate::account::profile_mint::{ProfileMintDoor, ProfileMintAvailability}`'s shape: a trait a
//! surface can hold and test against a double that cannot spend, and an availability enum with a
//! named arm for every reason a mint cannot be offered -- never a bare bool, because a bool cannot
//! tell a card WHY to refuse, and a card that cannot say why renders a dead control instead of a
//! reason (`ProfileMintAvailability::NoLineageWalk`'s own doc: *"Offering a mint here spends real
//! XCH on a profile that can never finish."*).
//!
//! # dig-account 0.29.0 closes the facade gap this module previously described
//!
//! `dig-account` 0.28.0 already replaced the candidate two-call signing chain with ONE call,
//! [`dig_account::mint::reward_distributor::begin_reward_distributor_mint`], which builds the
//! manager singleton, the launch offer, the distributor launcher, the eve singleton and the
//! reserve CAT, gates every requirement, signs the whole composition, and returns a
//! [`SignedRewardDistributorMint`] -- ready for [`SpendPublisher::push`]. What 0.28.0 still lacked
//! was a way for dig-app to hold the key that call needs without ever touching a raw
//! `WalletKey`/seed (`account::money_signer`'s own doc: "the seed never crosses this boundary").
//! `dig-account` 0.29.0 closes that gap: [`UnlockedAccount::reward_distributor_minter`]
//! (DIG-Network/dig-account#60) returns a [`RewardDistributorMinter`] that re-derives its key from
//! the LIVE seed on every call and hands out no key material at all -- the same shape
//! `UnlockedAccount::profile_minter` already gives `ProfileMintDoor`. [`DistributorMint`] now
//! holds a [`RewardDistributorMinter`] obtained PER CALL from
//! [`AccountResidency::reward_distributor_minter`] (mirroring `residency.rs`'s own
//! `profile_minter()`), never cached -- a minter derived once and kept would go on spending after
//! a lock-now, the same reasoning `profile_minter`'s doc states.
//!
//! # CREATE derives NO slots, and must not
//!
//! `dig-rewards-coin` 0.7 carries the PHANTOM SLOT hazard (dig_ecosystem#3357):
//! `created_slot_value_to_slot` on a distributor rebuilt from a chain read for an earlier
//! generation builds a slot that CURRIES cleanly and SIGNS cleanly, and the network then refuses
//! the resulting spend as `UnknownUnspent` -- a failure that appears only at push time, after the
//! user has been shown a working-looking ceremony. A launch creates a distributor that has no
//! entries, no commitments and no rewards yet, so this module derives no slot at all and never
//! calls that function; any future code here that needs one must take it from
//! `DistributorSnapshot::{entry_slot, commitment_slots, reward_slots}`, which report the slots the
//! chain actually has. Refill -- the one flow that does need slots -- is deliberately NOT built
//! here (dig-node#620 unmerged, the #3357 audit open).
//!
//! # What this module does NOT do
//!
//! No card in this crate is wired to a handler that builds and discards a
//! [`SignedRewardDistributorMint`] instead of pushing it -- dig_ecosystem#3253's own bar: **either
//! the flow signs and pushes, or there is no button.** [`DistributorMint::begin`] always pushes
//! through [`SpendPublisher`] before returning; there is no path that signs without pushing.

use chia_protocol::{Bytes32, Coin};
use chia_wallet_sdk::chia::consensus::consensus_constants::ConsensusConstants;
use chia_wallet_sdk::driver::Cat;
use dig_account::mint::reward_distributor::RewardDistributorMintRequest;
use dig_account::mint::{ChainUnavailable, MintError, MintNetwork, PushOutcome, SpendPublisher};
use dig_account::RewardDistributorMinter;
use dig_chainsource_interface::ChainSource;
use dig_rewards_coin::state::read_distributor;
use dig_rewards_coin::LaunchComment;

use crate::account::profile_mint::ChainReadiness;
use crate::account::residency::AccountResidency;

use super::client::DistributorChainState;
use super::create::Launchable;

/// Everything a distributor mint needs EXCEPT the manager puzzle -- deliberately.
///
/// `dig_account::mint::reward_distributor::RewardDistributorMintRequest` carries the manager inner
/// puzzle as a `pub` field over a `pub` enum, so a caller holding one can name
/// `ManagerInnerPuzzle::SingleKeyBuiltHere(pk)` directly and mint a distributor with no warning
/// shown and no manager choice witnessed. This struct is that request MINUS that one field: the
/// manager puzzle can only enter through [`DistributorMintDoor::begin`]'s [`Launchable`], which is
/// reachable only through `CreationGate -> WarningsShown -> Acknowledged -> ManagerChoiceMade ->
/// Launchable` (see [`super::create`]). Every field here is money and timing a caller legitimately
/// chooses; none of them is a provenance claim.
#[derive(Debug, Clone)]
pub struct DistributorMintTerms {
    /// The confirmed, unspent XCH coin at this wallet's own puzzle hash that funds the launch.
    pub funding: Coin,
    /// The $DIG CAT whose WHOLE amount becomes the distributor's reserve.
    pub reward_cat: Cat,
    /// The distributor's curried epoch length, in seconds.
    pub distributor_epoch_seconds: u64,
    /// When the first epoch starts, in unix seconds.
    pub first_epoch_start: u64,
    /// The launch comment binding this distributor to its store and root.
    pub generation: LaunchComment,
    /// The network fee to attach, in mojos.
    pub fee: u64,
    /// The signer's own clock, in unix seconds.
    pub now_unix_seconds: u64,
}

/// The one door a distributor mint may be driven through -- mirrors `ProfileMintDoor`'s shape.
///
/// Sealed (`private::Sealed`) so an external crate cannot supply a fake implementor that reports
/// success with nothing behind it -- the same shape of defect dig_ecosystem#3253 withdrew a whole
/// PR over. `Sized`, and [`Self::begin`] takes `self` BY VALUE, because a door is single-use: it
/// signs and pushes real money exactly once, and a `&self` door could be driven twice from one
/// handle. That rules out `&dyn DistributorMintDoor`; a surface holds
/// `Option<DistributorMint<..>>` instead and gets `None` when
/// [`DistributorMintAvailability::probe`] is not [`DistributorMintAvailability::Possible`].
pub trait DistributorMintDoor: private::Sealed + Sized {
    /// Sign a mint of `launchable`'s manager puzzle on `terms` and push it through this door's
    /// [`SpendPublisher`] in one call. Spends real XCH and $DIG the moment this returns `Ok` --
    /// there is no signed-but-unpushed state a caller can observe or discard; see this module's
    /// doc comment for why that shape is deliberate.
    ///
    /// Consumes BOTH the door and the [`Launchable`]: the door because a mint is single-use, and
    /// the `Launchable` because it is the terminal of the acknowledgement ladder and
    /// [`Launchable::into_manager_inner_puzzle`] -- the only producer of a real
    /// `ManagerInnerPuzzle` in dig-app -- consumes it in turn. This signature is what makes the
    /// ladder load-bearing rather than advisory: there is no way to reach this call with a manager
    /// puzzle the ladder did not witness.
    ///
    /// # Errors
    ///
    /// Any [`MintError`] `begin_reward_distributor_mint` returns (funds, gate refusal, build
    /// failure), or [`DistributorMintError::ChainUnavailable`] if the signed bundle could not be
    /// pushed.
    fn begin(
        self,
        launchable: Launchable,
        terms: DistributorMintTerms,
    ) -> Result<PendingDistributorMint, DistributorMintError>;
}

/// The sealing boundary for [`DistributorMintDoor`] -- `private` is not `pub`, so
/// `private::Sealed` cannot be named, let alone implemented, outside this crate.
mod private {
    pub trait Sealed {}
}

/// Why [`DistributorMintDoor::begin`] did not produce a [`PendingDistributorMint`].
#[non_exhaustive]
#[derive(Debug)]
pub enum DistributorMintError {
    /// `begin_reward_distributor_mint` itself refused, ran out of funds, or failed to build.
    Mint(MintError),
    /// The signed bundle could not be pushed -- the outcome is UNKNOWN, never "rejected".
    ChainUnavailable(String),
}

impl std::fmt::Display for DistributorMintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mint(err) => write!(f, "{err}"),
            Self::ChainUnavailable(why) => write!(f, "could not push the signed mint: {why}"),
        }
    }
}

impl std::error::Error for DistributorMintError {}

impl From<MintError> for DistributorMintError {
    fn from(err: MintError) -> Self {
        Self::Mint(err)
    }
}

impl From<ChainUnavailable> for DistributorMintError {
    fn from(err: ChainUnavailable) -> Self {
        Self::ChainUnavailable(err.to_string())
    }
}

/// A concrete [`DistributorMintDoor`] over a live [`RewardDistributorMinter`], [`ChainSource`]
/// and [`SpendPublisher`].
///
/// The minter is BORROWED, never owned and never cloned into this door: the caller obtains it from
/// [`AccountResidency::reward_distributor_minter`] for this one ceremony and drops it after, so a
/// lock-now during the ceremony makes the very next derivation refuse with `MintError::Locked`
/// rather than signing against an unlock that has ended.
pub struct DistributorMint<'a, C: ?Sized, P: ?Sized> {
    minter: &'a RewardDistributorMinter,
    network: MintNetwork,
    consensus_constants: &'a ConsensusConstants,
    chain: &'a C,
    publisher: &'a P,
}

impl<'a, C, P> DistributorMint<'a, C, P>
where
    C: ChainSource + ?Sized,
    P: SpendPublisher + ?Sized,
{
    /// Builds a door over `minter`, signing for `network` under `consensus_constants`, reading
    /// `chain` and pushing through `publisher`.
    pub fn new(
        minter: &'a RewardDistributorMinter,
        network: MintNetwork,
        consensus_constants: &'a ConsensusConstants,
        chain: &'a C,
        publisher: &'a P,
    ) -> Self {
        Self {
            minter,
            network,
            consensus_constants,
            chain,
            publisher,
        }
    }
}

impl<C, P> private::Sealed for DistributorMint<'_, C, P>
where
    C: ChainSource + ?Sized,
    P: SpendPublisher + ?Sized,
{
}

impl<C, P> DistributorMintDoor for DistributorMint<'_, C, P>
where
    C: ChainSource + ?Sized,
    P: SpendPublisher + ?Sized,
{
    fn begin(
        self,
        launchable: Launchable,
        terms: DistributorMintTerms,
    ) -> Result<PendingDistributorMint, DistributorMintError> {
        // The ONE place in dig-app that builds this request (pinned by
        // `the_mint_request_is_built_only_here`), and therefore the one place a
        // `ManagerInnerPuzzle` can enter a signed mint -- always through the ladder's own
        // `Launchable`, never from a caller-supplied literal.
        let request = RewardDistributorMintRequest {
            funding: terms.funding,
            reward_cat: terms.reward_cat,
            manager_inner_puzzle: launchable.into_manager_inner_puzzle(),
            distributor_epoch_seconds: terms.distributor_epoch_seconds,
            first_epoch_start: terms.first_epoch_start,
            generation: terms.generation,
            fee: terms.fee,
            now_unix_seconds: terms.now_unix_seconds,
        };

        // Recorded BEFORE the push, deliberately -- see `PendingMint::pushed_at_height`'s own doc
        // in dig-account for why: a floor a later reconciliation needs even if the push's own
        // outcome comes back unknown. `Ok(None)` (no peak known) is recorded as `None`, never
        // faked to zero.
        let peak_before_push = self.chain.peak_height().ok().flatten();

        let signed = self
            .minter
            .begin(&request, &self.network, self.consensus_constants)?;

        let push = self.publisher.push(signed.bundle())?;

        Ok(PendingDistributorMint {
            predicted_distributor_launcher_id: signed.predicted_distributor_launcher_id(),
            predicted_manager_launcher_id: signed.predicted_manager_launcher_id(),
            push,
            peak_before_push,
        })
    }
}

/// A distributor mint that has been SIGNED AND PUSHED, and is not yet proven on chain.
///
/// Every field is `pub(crate)`-readable only through the accessors below; there is no public
/// struct literal and no `Default` -- the only way to obtain one is
/// [`DistributorMintDoor::begin`], after a real push actually happened.
#[derive(Debug, Clone)]
pub struct PendingDistributorMint {
    predicted_distributor_launcher_id: Bytes32,
    predicted_manager_launcher_id: Bytes32,
    push: PushOutcome,
    peak_before_push: Option<u32>,
}

impl PendingDistributorMint {
    /// The distributor singleton's launcher id, predicted from the signed bundle's own spends. No
    /// coin with this id exists until the bundle confirms.
    pub fn predicted_distributor_launcher_id(&self) -> Bytes32 {
        self.predicted_distributor_launcher_id
    }

    /// The manager singleton's launcher id, predicted the same way.
    pub fn predicted_manager_launcher_id(&self) -> Bytes32 {
        self.predicted_manager_launcher_id
    }

    /// What the mempool said when this bundle was pushed.
    pub fn push_outcome(&self) -> &PushOutcome {
        &self.push
    }

    /// The chain's peak immediately before this mint was pushed, if the chain source reported one.
    pub fn peak_before_push(&self) -> Option<u32> {
        self.peak_before_push
    }

    /// Reads `chain` for this pending mint's current liveness.
    ///
    /// This is the ONLY place [`DistributorMintLiveness::OnChain`] is constructed, and only from a
    /// successful [`dig_rewards_coin::state::read_distributor`] naming THIS pending mint's own
    /// predicted distributor launcher id -- never from the push outcome alone, which proves only
    /// that a mempool accepted the bundle, not that it confirmed.
    pub fn poll<C>(&self, chain: &C) -> DistributorMintLiveness
    where
        C: ChainSource,
    {
        match read_distributor(chain, self.predicted_distributor_launcher_id) {
            Ok(Some(snapshot)) => DistributorMintLiveness::OnChain(ConfirmedDistributor(Box::new(
                super::client::distributor_chain_state_from_snapshot(&snapshot),
            ))),
            Ok(None) => DistributorMintLiveness::Submitted,
            Err(_) => DistributorMintLiveness::Unknown,
        }
    }
}

/// How alive a [`PendingDistributorMint`] looks, from a fresh chain read.
///
/// `Unknown` is a DIFFERENT claim from `Submitted`: `Submitted` means the chain was READ and the
/// distributor genuinely does not exist there yet (still early, or the mempool dropped it);
/// `Unknown` means the chain COULD NOT be read at all. Collapsing the two would let a transport
/// failure render as "not yet on chain" -- a claim about the chain's STATE this build has no basis
/// to make when the chain could not even answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributorMintLiveness {
    /// The bundle was pushed; `read_distributor` was asked and answered "no such distributor yet."
    Submitted,
    /// `read_distributor` found this distributor on chain -- see [`ConfirmedDistributor`], whose
    /// private field is what makes this variant unforgeable.
    OnChain(ConfirmedDistributor),
    /// The chain could not be read. Not evidence of absence, and not evidence of presence.
    Unknown,
}

/// A [`DistributorChainState`] that a successful `read_distributor` actually returned.
///
/// # Why this newtype exists
///
/// Rust enum variants carry no privacy of their own: while
/// [`DistributorMintLiveness::OnChain`] held a `Box<DistributorChainState>` -- an all-`pub`-field
/// struct ([`super::client::DistributorChainState`]) -- any crate could write
/// `DistributorMintLiveness::OnChain(Box::new(DistributorChainState { .. }))` from a
/// [`PushOutcome`] alone and render "created, reserve on chain, observed at <now>" over a bundle
/// that never confirmed, with a fabricated `observed_at` and a merely PREDICTED launcher id
/// painted as a settled identity. The module doc and `SPEC.md` §11 clause 2 both asserted that was
/// impossible, so both shipped false (dig-app#411 adversarial + security gates).
///
/// The private field closes it: the tuple-struct constructor is private to this module, so
/// [`PendingDistributorMint::poll`] is the only expression anywhere that can produce one, and it
/// can only do so from `Ok(Some(snapshot))` of a `read_distributor` naming the pending mint's own
/// predicted launcher id. Readers get the state through [`Self::state`].
///
/// The forging line no longer compiles:
///
/// ```compile_fail,E0603
/// use dig_app_core::rewards::client::DistributorChainState;
/// use dig_app_core::rewards::mint::{ConfirmedDistributor, DistributorMintLiveness};
///
/// let never_confirmed = DistributorChainState {
///     launcher_id: [0; 32],
///     reserve_asset_id: [0; 32],
///     reserve_base_units: 0,
///     entry_count: 0,
///     current_distributor_epoch_start: 0,
///     last_entry_write_at: None,
///     observed_at: 0,
/// };
/// // error[E0603]: tuple struct constructor `ConfirmedDistributor` is private
/// let forged = DistributorMintLiveness::OnChain(ConfirmedDistributor(Box::new(never_confirmed)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedDistributor(Box<DistributorChainState>);

impl ConfirmedDistributor {
    /// The chain state this confirmation carries -- read-only, because there is no way to build a
    /// `ConfirmedDistributor` around a state the chain did not just answer with.
    pub fn state(&self) -> &DistributorChainState {
        &self.0
    }
}

/// Whether this build can mint a reward distributor, and when it cannot, why -- mirrors
/// `ProfileMintAvailability` exactly: a named arm per refusal, never a bare bool, so a card can
/// render the REASON instead of a dead control.
///
/// Every arm is decided by [`probe`](Self::probe) from facts that CHANGE while the app runs -- is
/// the account unlocked, does the chain answer -- so each of them is reachable. The previous
/// `NoMinterFacade` arm was returned by a `const fn` and could therefore never be anything else;
/// it is deleted here rather than kept, for the reason this module already deleted `NoSigningSeam`
/// (an arm naming a cause that has stopped being true is a doc lie), and the same reason the
/// availability had to become a probe at all: a constant cannot report a state that moves.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributorMintAvailability {
    /// A distributor mint may be attempted: the account is unlocked, so a live
    /// [`RewardDistributorMinter`] exists, and the chain answers the reads a launch needs.
    ///
    /// Not a promise that the mint will succeed -- the money gates
    /// (`begin_reward_distributor_mint`'s own: an unowned funding coin or reward CAT, insufficient
    /// funds, a zero epoch) run at [`DistributorMintDoor::begin`] and refuse there.
    Possible,
    /// The account is locked, so there is no minter to build a door from.
    ///
    /// The first question asked, and answered without touching the network: a locked app is told
    /// to unlock rather than made to wait on a node round trip for a refusal the unlock decides.
    Locked,
    /// The chain answers ordinary reads and cannot walk a singleton lineage -- so the launch could
    /// be signed and pushed, and then never confirmed against a lineage this build can follow.
    /// The verbatim reason lives on [`ChainReadiness::NoLineageWalk`]; this arm carries only the
    /// fact, so a card can be painted from a `Copy` value.
    NoLineageWalk,
    /// The chain could not be reached at all. Never rendered as *no coins* or *not eligible*: the
    /// chain was not asked and answered, it did not answer.
    NoChainTransport,
}

impl DistributorMintAvailability {
    /// Ask the two questions a launch depends on -- is there an unlocked account, and does the
    /// chain answer -- and report the first refusal.
    ///
    /// The unlock is asked FIRST, and locally: a locked app needs no node round trip to learn that
    /// it must unlock, and asking the chain first would make every locked app wait on the network
    /// for a refusal the unlock already decided.
    ///
    /// The chain question routes through [`ChainReadiness::probe`] rather than re-deriving one
    /// here, so there is exactly one expression in this crate of what *a usable chain* means
    /// (`ProfileMintSeams::from_readiness` is the other consumer of that same answer).
    pub fn probe<C>(residency: &AccountResidency, chain: &C) -> Self
    where
        C: ChainSource + ?Sized,
    {
        if residency.reward_distributor_minter().is_none() {
            return Self::Locked;
        }

        match ChainReadiness::probe(chain) {
            ChainReadiness::WalksLineages => Self::Possible,
            ChainReadiness::NoLineageWalk { .. } => Self::NoLineageWalk,
            ChainReadiness::NoChainTransport { .. } => Self::NoChainTransport,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::SpendBundle;
    use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;
    use dig_chainsource_interface::CoinRecord;
    use dig_chainsource_interface::{ChainSourceError, MockChainSource};

    use crate::account::residency::test_support::residency;
    use crate::rewards::create::{ManagerChoice, ManagerChoiceMade};
    use crate::rewards::pane::{CreationGate, WarningsShown, REQUIRED_WARNING_KEYS};
    use crate::session_lock::SessionKeys;

    /// A [`SpendPublisher`] double that always reports acceptance and KEEPS what it was handed --
    /// this module's own mirror of `ProfileMint`'s test publisher, never wired to a real
    /// transport. The capture is what lets a test confirm the very bundle the door signed into a
    /// mock chain and then read it back, instead of hand-listing what the mint is believed to
    /// build.
    #[derive(Default)]
    struct AcceptingPublisher {
        pushed: std::cell::RefCell<Vec<SpendBundle>>,
    }

    impl AcceptingPublisher {
        /// The one bundle this publisher was handed. Panics if it was handed none or more than
        /// one -- both would make whatever a test asserted next about the wrong bundle.
        fn only_bundle(&self) -> SpendBundle {
            let pushed = self.pushed.borrow();
            assert_eq!(pushed.len(), 1, "exactly one bundle must have been pushed");
            pushed[0].clone()
        }
    }

    impl SpendPublisher for AcceptingPublisher {
        fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome, ChainUnavailable> {
            self.pushed.borrow_mut().push(bundle.clone());
            Ok(PushOutcome::Accepted)
        }
    }

    struct FailingPublisher;

    impl SpendPublisher for FailingPublisher {
        fn push(&self, _bundle: &SpendBundle) -> Result<PushOutcome, ChainUnavailable> {
            Err(ChainUnavailable::new("no peer"))
        }
    }

    /// An unlocked residency and the LIVE minter it yields -- the same two calls production makes.
    ///
    /// The residency is returned alongside the minter and must be held by the caller: it owns the
    /// unlock the minter observes, so dropping it would relock the account underneath the door.
    fn fixture_minter() -> (AccountResidency, RewardDistributorMinter) {
        let residency = residency();
        let minter = residency
            .reward_distributor_minter()
            .expect("a freshly enrolled residency is unlocked");
        (residency, minter)
    }

    /// Builds one real CAT coin lineage (a parent CAT coin spent into one child of the same amount,
    /// both curried to `p2_public_key`) and loads it into a [`MockChainSource`], so the reward CAT a
    /// mint spends is resolved by dig-account's own `dig_cat_coins` over real CLVM bytes rather than
    /// hand-built.
    ///
    /// Takes the public key, not a puzzle hash: `Cat::parse_children` derives the child's
    /// `p2_puzzle_hash` STRUCTURALLY from the parent's real inner puzzle reveal, so the puzzle built
    /// here must be curried to the SAME key the resulting coin is treated as belonging to.
    ///
    /// Lived in `rewards::cat_coins` until dig-account 0.29.0 shipped `dig_cat_coins` (#59) and that
    /// module -- a mirror of dig-account's private resolver -- was deleted; only the fixture the
    /// tests below actually drive moved here.
    fn fixture_cat_lineage(p2_public_key: chia_bls::PublicKey, amount: u64) -> MockChainSource {
        use chia_puzzle_types::standard::StandardArgs;
        use chia_wallet_sdk::driver::{CatInfo, CatSpend, SpendContext, StandardLayer};
        use chia_wallet_sdk::prelude::{Conditions, SpendWithConditions};
        use dig_constants::DIG_ASSET_ID;

        let p2_puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(p2_public_key).into();
        let cat_puzzle_hash: Bytes32 =
            chia_puzzle_types::cat::CatArgs::curry_tree_hash(DIG_ASSET_ID, p2_puzzle_hash.into())
                .into();

        let parent_coin = Coin::new(Bytes32::from([1u8; 32]), cat_puzzle_hash, amount);

        let mut ctx = SpendContext::new();
        // The INNER puzzle hash, never the curried CAT hash: a CAT's inner puzzle emits its
        // `CREATE_COIN` against the inner (p2) hash and the CAT layer morphs it into the curried
        // one. Naming the curried hash here builds a child whose coin id is not the one computed
        // below, so `Cat::parse_children` finds no match.
        let inner_spend = StandardLayer::new(p2_public_key)
            .spend_with_conditions(
                &mut ctx,
                Conditions::new().create_coin(
                    p2_puzzle_hash,
                    amount,
                    chia_puzzle_types::Memos::None,
                ),
            )
            .expect("build inner spend");
        let cat = Cat::new(
            parent_coin,
            None,
            CatInfo::new(DIG_ASSET_ID, None, p2_puzzle_hash),
        );
        Cat::spend_all(&mut ctx, &[CatSpend::new(cat, inner_spend)]).expect("build CAT spend");
        let parent_spend = ctx
            .take()
            .into_iter()
            .find(|cs| cs.coin.coin_id() == parent_coin.coin_id())
            .expect("parent CAT spend present");

        let child_coin = Coin::new(parent_coin.coin_id(), cat_puzzle_hash, amount);

        // `ChainSource::parent_spend(child_id)` resolves `coin_record(child_id)` then
        // `coin_spend(record.coin.parent_coin_info)` -- so the spend is keyed by the PARENT's id.
        MockChainSource::new()
            .with_coin(
                child_coin.coin_id(),
                CoinRecord {
                    coin: child_coin,
                    confirmed_height: Some(10),
                    spent_height: None,
                    timestamp: None,
                    coinbase: false,
                },
            )
            .with_spend(parent_coin.coin_id(), parent_spend)
    }

    /// A [`Launchable`] reached the ONLY way production can reach one: the five required warning
    /// keys shown, the gate acknowledged with that witness, and a manager choice witnessed for the
    /// exact value being launched. Mirrors `super::super::create::witness_tests::acknowledged`
    /// rather than short-cutting the ladder, because the ladder is what
    /// [`DistributorMintDoor::begin`]'s signature now requires.
    fn fixture_launchable(manager_key: chia_bls::PublicKey) -> Launchable {
        let shown = WarningsShown::having_displayed(&REQUIRED_WARNING_KEYS)
            .expect("the five required keys must produce a witness");
        let choice = ManagerChoice::SingleKeyBuiltHere(manager_key);
        let made = ManagerChoiceMade::for_choice(&choice);
        CreationGate::unacknowledged()
            .acknowledge(shown)
            .with_manager_choice(made, choice)
    }

    /// Builds a funded, curried CAT reserve coin at `wallet`'s own puzzle hash, with a proven
    /// lineage loaded into a fresh [`MockChainSource`] -- exactly what
    /// [`DistributorMintTerms::reward_cat`] needs to pass `begin_reward_distributor_mint`'s
    /// ownership gate. Returns the terms alongside the chain they were built against, since
    /// [`MockChainSource`] has no in-place merge -- the whole chain is assembled in one builder
    /// expression instead.
    ///
    /// Carries NO manager puzzle: that is the whole point of [`DistributorMintTerms`]. The manager
    /// puzzle enters through the [`Launchable`] every caller of `begin` must supply.
    fn fixture_terms(
        minter: &RewardDistributorMinter,
        now: u64,
    ) -> (DistributorMintTerms, MockChainSource) {
        let p2_puzzle_hash = minter
            .puzzle_hash()
            .expect("an unlocked minter has a puzzle hash");
        let public_key = minter
            .public_key()
            .expect("an unlocked minter has a public key");

        let funding = Coin::new(Bytes32::from([2u8; 32]), p2_puzzle_hash, 1_000_000);

        let chain = fixture_cat_lineage(public_key, 10_000).with_coin(
            funding.coin_id(),
            CoinRecord {
                coin: funding,
                confirmed_height: Some(10),
                spent_height: None,
                timestamp: None,
                coinbase: false,
            },
        );

        // Through the production listing, not a hand-built `Cat`: this is the very call the coin
        // picker makes, so a fixture that resolved lineage some other way would prove the door over
        // a coin no card could have offered.
        let listing = minter
            .dig_cat_coins(&chain)
            .expect("the fixture lineage resolves through dig-account's own resolver");
        assert_eq!(listing.omitted(), 0, "the fixture holds one candidate");
        let reward_cat = *listing
            .cats()
            .first()
            .expect("the fixture's $DIG coin is listed");

        let terms = DistributorMintTerms {
            funding,
            reward_cat,
            distributor_epoch_seconds: 604_800,
            first_epoch_start: now + 3_600,
            generation: LaunchComment::new(Bytes32::from([9u8; 32]), Bytes32::from([9u8; 32])),
            fee: 0,
            now_unix_seconds: now,
        };

        (terms, chain)
    }

    /// Loads `bundle` into `chain` as if every one of its spends had CONFIRMED at `height`: each
    /// spent coin gets a record and its spend, every coin the spends create gets a record of its
    /// own, and the chain reports `height` as its peak at `timestamp`.
    ///
    /// The created coins are derived by RUNNING each puzzle against its own solution and reading
    /// the `CREATE_COIN` conditions -- the same thing a node does -- rather than by hand-listing
    /// what the mint is believed to build. That is what makes the resulting chain a real subject
    /// for `read_distributor`: the launcher spend, the eve spend, the eve-era zero-amount reserve
    /// and the tip reserve are all present because the bundle genuinely creates them.
    ///
    /// The singleton lineage is the one thing a bundle cannot supply (a real source authenticates
    /// it against the chain), so every coin id this bundle touches is declared a member. This
    /// fixture therefore proves nothing about lineage AUTHENTICATION -- `read_distributor`'s own
    /// `lineage.contains` check is satisfied, not exercised.
    fn confirm_bundle(
        chain: MockChainSource,
        bundle: &SpendBundle,
        launcher_id: Bytes32,
        height: u32,
        timestamp: u64,
    ) -> MockChainSource {
        use chia_sdk_types::{run_puzzle, Condition};
        use clvm_traits::FromClvm;
        use clvmr::serde::node_from_bytes;
        use clvmr::{Allocator, NodePtr};
        use dig_chainsource_interface::SingletonLineage;

        let mut chain = chain;
        let mut allocator = Allocator::new();
        let mut members = Vec::new();
        let mut created = Vec::new();

        let spent_ids: std::collections::HashSet<Bytes32> = bundle
            .coin_spends
            .iter()
            .map(|spend| spend.coin.coin_id())
            .collect();

        for spend in &bundle.coin_spends {
            let coin_id = spend.coin.coin_id();
            members.push(coin_id);
            chain = chain
                .with_coin(
                    coin_id,
                    CoinRecord {
                        coin: spend.coin,
                        confirmed_height: Some(height - 1),
                        spent_height: Some(height),
                        timestamp: Some(timestamp),
                        coinbase: false,
                    },
                )
                .with_spend(coin_id, spend.clone());

            let puzzle = node_from_bytes(&mut allocator, spend.puzzle_reveal.as_ref())
                .expect("puzzle reveal decodes");
            let solution =
                node_from_bytes(&mut allocator, spend.solution.as_ref()).expect("solution decodes");
            let output = run_puzzle(&mut allocator, puzzle, solution).expect("puzzle runs");
            let conditions =
                Vec::<NodePtr>::from_clvm(&allocator, output).expect("conditions are a list");
            for condition in conditions {
                if let Ok(Condition::CreateCoin(create)) =
                    Condition::<NodePtr>::from_clvm(&allocator, condition)
                {
                    created.push(chia_protocol::Coin::new(
                        coin_id,
                        create.puzzle_hash,
                        create.amount,
                    ));
                }
            }
        }

        for coin in created {
            let coin_id = coin.coin_id();
            members.push(coin_id);
            if spent_ids.contains(&coin_id) {
                continue;
            }
            chain = chain.with_coin(
                coin_id,
                CoinRecord {
                    coin,
                    confirmed_height: Some(height),
                    spent_height: None,
                    timestamp: Some(timestamp),
                    coinbase: false,
                },
            );
        }

        chain
            .with_peak(height)
            .with_timestamp(height, timestamp)
            .with_lineage(launcher_id, SingletonLineage::new(launcher_id, members))
    }

    /// (a) A door over a fixture wallet, a funded mock chain and an accepting publisher drives a
    /// real `begin_reward_distributor_mint` end to end: `begin` returns a `PendingDistributorMint`
    /// whose `poll` reports `Submitted` while the chain has not seen the launch, and `OnChain`
    /// once the very bundle the door signed is confirmed into that chain.
    ///
    /// # What breaks this test
    ///
    /// Flipping `poll`'s `Ok(Some(snapshot)) => OnChain(..)` arm to `Unknown` turns this RED at the
    /// final assertion -- the vacuous-proof defect the dig-app#411 reviewer found: every earlier
    /// revision of this test asserted `Submitted` only, so no test in this crate ever produced
    /// `OnChain` and that flip stayed green. Returning a `Submitted` there breaks it too.
    #[test]
    fn begin_drives_a_real_mint_to_submitted_then_on_chain() {
        let (_residency, minter) = fixture_minter();
        let now = 2_000_000_000;
        let (terms, chain) = fixture_terms(&minter, now);
        let publisher = AcceptingPublisher::default();
        let network = MintNetwork::mainnet();

        let manager_key = minter.public_key().expect("unlocked");
        let door = DistributorMint::new(&minter, network, &MAINNET_CONSTANTS, &chain, &publisher);
        let pending = door
            .begin(fixture_launchable(manager_key), terms)
            .expect("mint begins");

        assert_eq!(pending.push_outcome(), &PushOutcome::Accepted);
        assert_eq!(pending.poll(&chain), DistributorMintLiveness::Submitted);

        let launcher_id = pending.predicted_distributor_launcher_id();
        let confirmed = confirm_bundle(chain, &publisher.only_bundle(), launcher_id, 20, now);

        match pending.poll(&confirmed) {
            DistributorMintLiveness::OnChain(distributor) => assert_eq!(
                distributor.state().launcher_id,
                launcher_id.to_bytes(),
                "the confirmed state must be THIS mint's own distributor"
            ),
            other => panic!("a confirmed launch must read as OnChain, got {other:?}"),
        }
    }

    /// (b) A chain read failure during `poll` reports `Unknown`, never `OnChain` and never
    /// `Submitted` -- an unanswerable read must not be read as either presence or absence.
    #[test]
    fn poll_reports_unknown_on_a_chain_read_failure() {
        let (_residency, minter) = fixture_minter();
        let (terms, chain) = fixture_terms(&minter, 2_000_000_000);
        let publisher = AcceptingPublisher::default();
        let network = MintNetwork::mainnet();

        let manager_key = minter.public_key().expect("unlocked");
        let door = DistributorMint::new(&minter, network, &MAINNET_CONSTANTS, &chain, &publisher);
        let pending = door
            .begin(fixture_launchable(manager_key), terms)
            .expect("mint begins");

        let failing_chain =
            MockChainSource::new().fail_with(ChainSourceError::Transport("no peer".into()));
        assert!(matches!(
            pending.poll(&failing_chain),
            DistributorMintLiveness::Unknown
        ));
    }

    /// The manager puzzle can enter a signed mint through exactly one expression in dig-app: the
    /// `RewardDistributorMintRequest` literal inside [`DistributorMintDoor::begin`], which sources
    /// it from a [`Launchable`]. A second construction site anywhere in this crate would re-open
    /// the bypass the dig-app#411 adversarial gate found (finding F2): dig-account's request
    /// struct has all-`pub` fields and `ManagerInnerPuzzle::SingleKeyBuiltHere` is a public
    /// variant, so a caller who can build the request can mint with no warning shown and no
    /// manager choice witnessed.
    ///
    /// Scans this crate's whole `src` tree rather than one file, because the defect is a NEW call
    /// site appearing somewhere else. Comment lines are stripped and the needle is assembled from
    /// pieces for the reason `super::pane`'s no-control scan does the same: an unassembled needle
    /// matches this test's own source.
    #[test]
    fn the_mint_request_is_built_only_here() {
        let needle = format!("{}{} {{", "RewardDistributor", "MintRequest");
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let this_file = src.join("rewards").join("mint.rs");

        let mut found_here = false;
        let mut sources = vec![src];
        while let Some(path) = sources.pop() {
            for entry in std::fs::read_dir(&path).expect("the crate's src tree is readable") {
                let entry = entry.expect("a readable directory entry").path();
                if entry.is_dir() {
                    sources.push(entry);
                    continue;
                }
                if entry.extension() != Some(std::ffi::OsStr::new("rs")) {
                    continue;
                }
                let code_only: String = std::fs::read_to_string(&entry)
                    .expect("a readable source file")
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("//"))
                    .collect::<Vec<_>>()
                    .join("\n");
                if !code_only.contains(&needle) {
                    continue;
                }
                assert_eq!(
                    entry, this_file,
                    "only rewards/mint.rs may build a {needle:?} -- every other site bypasses the \
                     acknowledgement ladder"
                );
                found_here = true;
            }
        }

        assert!(
            found_here,
            "the scan found no {needle:?} at all -- it would pass over a crate that had deleted \
             the door entirely"
        );
    }

    /// (d) The availability probe FIRES: an unlocked residency over an answering chain reports
    /// `Possible`, and the SAME residency reports `Locked` once it locks.
    ///
    /// Both halves in one test on purpose. The defect this replaces was a `const fn current()` that
    /// could only ever return one arm, and a test asserting only the refusal would have passed over
    /// it unchanged -- as the previous availability re-pin did for two releases. What makes this a
    /// measurement rather than a restatement is that ONE subject produces two different answers as
    /// its state moves.
    ///
    /// # What breaks this test
    ///
    /// Making `probe` return `Locked` unconditionally (dropping the `is_none()` check) turns the
    /// first assertion RED; making it return `Possible` unconditionally turns the second RED.
    #[test]
    fn the_availability_probe_follows_the_unlock() {
        let residency = residency();
        let chain = MockChainSource::new();

        assert_eq!(
            DistributorMintAvailability::probe(&residency, &chain),
            DistributorMintAvailability::Possible,
            "an unlocked account over an answering chain can attempt a mint"
        );

        residency.lock_all();
        assert_eq!(
            DistributorMintAvailability::probe(&residency, &chain),
            DistributorMintAvailability::Locked,
            "a locked account has no minter, so no door can be built"
        );
    }

    /// An unreachable chain reports `NoChainTransport` -- never `Possible`, and never `Locked`,
    /// which would send somebody to unlock an account that is already unlocked.
    #[test]
    fn the_availability_probe_reports_an_unreachable_chain_as_transport() {
        let residency = residency();
        let unreachable =
            MockChainSource::new().fail_with(ChainSourceError::Transport("no peer".into()));

        assert_eq!(
            DistributorMintAvailability::probe(&residency, &unreachable),
            DistributorMintAvailability::NoChainTransport
        );
    }

    /// A push failure surfaces as `DistributorMintError::ChainUnavailable`, not as a successful
    /// `PendingDistributorMint` -- `begin` must not report a pending mint for a bundle that was
    /// never actually pushed.
    #[test]
    fn a_push_failure_is_refused_not_swallowed() {
        let (_residency, minter) = fixture_minter();
        let (terms, chain) = fixture_terms(&minter, 2_000_000_000);
        let publisher = FailingPublisher;
        let network = MintNetwork::mainnet();

        let manager_key = minter.public_key().expect("unlocked");
        let door = DistributorMint::new(&minter, network, &MAINNET_CONSTANTS, &chain, &publisher);
        let err = door
            .begin(fixture_launchable(manager_key), terms)
            .expect_err("push failed");
        assert!(matches!(err, DistributorMintError::ChainUnavailable(_)));
    }
}
