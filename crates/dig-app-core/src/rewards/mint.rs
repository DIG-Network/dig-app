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
//! `SignedRewardDistributorMint` -- ready for [`SpendPublisher::push`]. What 0.28.0 still lacked
//! was a way for dig-app to hold the key that call needs without ever touching a raw
//! `WalletKey`/seed (`account::money_signer`'s own doc: "the seed never crosses this boundary").
//! `dig-account` 0.29.0 closes that gap: `UnlockedAccount::reward_distributor_minter`
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
//! # Confirmation is dig-account's, not this crate's
//!
//! `dig-account` 0.30 owns the whole submit-and-confirm half: `SignedRewardDistributorMint::submit`
//! reads the peak BEFORE pushing (so an unreachable chain refuses with no bundle sent) and returns a
//! [`PendingRewardDistributor`], whose `status` answers `Confirmed` / `Awaiting` / `Failed` against
//! `SPEC.md` §6BB.7's five evidence rules, with a chain READ failure as `Err` rather than any
//! status. This module keeps NO confirmation convention of its own: the interim `poll` here, which
//! derived an `OnChain` from `dig_rewards_coin::state::read_distributor`, is deleted, because a
//! second convention can disagree with the one the crate proves -- and only one of them has a
//! simulator proof behind it (`a_submitted_mint_is_awaiting_then_confirmed_after_burial`).
//!
//! The settled identity comes with it: `ConfirmedRewardDistributor::distributor_launcher_id` is the
//! counterpart of the PREDICTED id a pending carries, and both evidence types have `pub(crate)`
//! constructors upstream -- so neither is wrapped in a newtype here. Wrapping one would add a
//! dig-app-side constructor to a value whose whole point is that only dig-account can make it.
//!
//! # What this module does NOT do
//!
//! No card in this crate is wired to a handler that builds and discards a
//! `SignedRewardDistributorMint` instead of pushing it -- dig_ecosystem#3253's own bar: **either
//! the flow signs and pushes, or there is no button.** [`DistributorMint::begin`] always pushes
//! through [`SpendPublisher`] before returning; there is no path that signs without pushing.

use chia_protocol::Coin;
use chia_wallet_sdk::chia::consensus::consensus_constants::ConsensusConstants;
use chia_wallet_sdk::driver::Cat;
use dig_account::mint::reward_distributor::RewardDistributorMintRequest;
use dig_account::mint::{MintNetwork, MintResult, SpendPublisher};
use dig_account::{PendingRewardDistributor, RewardDistributorMinter};
use dig_chainsource_interface::ChainSource;
use dig_rewards_coin::LaunchComment;

use crate::account::profile_mint::ChainReadiness;
use crate::account::residency::AccountResidency;

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
    /// Sign a mint of `launchable`'s manager puzzle on `terms` and submit it through this door's
    /// [`SpendPublisher`] in one call. Spends real XCH and $DIG the moment this returns `Ok` --
    /// there is no signed-but-unpushed state a caller can observe or discard; see this module's
    /// doc comment for why that shape is deliberate.
    ///
    /// The returned [`PendingRewardDistributor`] is the ONLY thing that can later say what became
    /// of this mint, through its own `status(&chain)`. A surface that holds one and never asks is
    /// the withdrawn-button defect inverted -- a spend with nothing watching it -- so the pane must
    /// ask on its refresh cadence for every pending mint it holds.
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
    /// Any `MintError` the signing seam returns (funds, gate refusal, build failure, a relocked
    /// account), `MintError::ChainUnreachable` if the peak could not be read or the push's outcome
    /// is unknown -- in which case the bundle was NOT necessarily lost and the identical bundle may
    /// be pushed again -- or `MintError::Rejected` if the mempool answered no, in which case no
    /// funds moved.
    fn begin(
        self,
        launchable: Launchable,
        terms: DistributorMintTerms,
    ) -> MintResult<PendingRewardDistributor>;
}

/// The sealing boundary for [`DistributorMintDoor`] -- `private` is not `pub`, so
/// `private::Sealed` cannot be named, let alone implemented, outside this crate.
mod private {
    pub trait Sealed {}
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

    /// Builds a door for mainnet, under mainnet's own [`ConsensusConstants`] -- mirrors
    /// `ProfileMint::for_session`'s own `MintNetwork::mainnet()` default. Lets a caller (the
    /// `create_sink` worker in `dig-app.rs`) build a door without depending on
    /// `chia-wallet-sdk`/`dig-account` directly for the constant this crate already carries.
    pub fn mainnet(minter: &'a RewardDistributorMinter, chain: &'a C, publisher: &'a P) -> Self {
        Self::new(
            minter,
            MintNetwork::mainnet(),
            &chia_wallet_sdk::prelude::MAINNET_CONSTANTS,
            chain,
            publisher,
        )
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
    ) -> MintResult<PendingRewardDistributor> {
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

        let signed = self
            .minter
            .begin(&request, &self.network, self.consensus_constants)?;

        // `submit` reads the peak BEFORE pushing, so an unreachable chain refuses here with no
        // bundle sent -- and the height it records is the floor its own `status` uses to reject a
        // confirmation the chain claims predates this broadcast.
        signed.submit(self.chain, self.publisher)
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
pub(crate) mod tests {
    use super::*;
    use chia_protocol::{Bytes32, SpendBundle};
    use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;
    use dig_account::mint::evidence::MIN_CONFIRMATION_DEPTH;
    use dig_account::mint::{ChainUnavailable, MintError, PushOutcome};
    use dig_account::RewardDistributorStatus;
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
    pub(crate) struct AcceptingPublisher {
        pushed: std::cell::RefCell<Vec<SpendBundle>>,
    }

    impl AcceptingPublisher {
        /// The one bundle this publisher was handed. Panics if it was handed none or more than
        /// one -- both would make whatever a test asserted next about the wrong bundle.
        pub(crate) fn only_bundle(&self) -> SpendBundle {
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
    pub(crate) fn fixture_minter() -> (AccountResidency, RewardDistributorMinter) {
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
    pub(crate) fn fixture_launchable(manager_key: chia_bls::PublicKey) -> Launchable {
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
    pub(crate) fn fixture_terms(
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

        // The peak is not decoration: `submit` reads it BEFORE pushing, so a chain that reports
        // none refuses the whole submission with `ChainUnreachable` and no bundle leaves.
        let chain = fixture_cat_lineage(public_key, 10_000)
            .with_coin(
                funding.coin_id(),
                CoinRecord {
                    coin: funding,
                    confirmed_height: Some(10),
                    spent_height: None,
                    timestamp: None,
                    coinbase: false,
                },
            )
            .with_peak(10)
            .with_timestamp(10, now);

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
    pub(crate) fn confirm_bundle(
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

    /// (a) A door over a live minter, a funded mock chain and an accepting publisher drives a real
    /// mint end to end: `begin` returns a `PendingRewardDistributor` whose `status` reports
    /// `Awaiting` while the chain has not seen the launch, and `Confirmed` once the very bundle the
    /// door signed is confirmed into that chain and buried `MIN_CONFIRMATION_DEPTH` blocks deep.
    ///
    /// The burial is what makes the second half a real measurement: confirming the bundle at the
    /// peak leaves the status `Awaiting`, because a launcher one block old is not evidence a
    /// reorg cannot take back. The settled id is compared against the PREDICTED one to pin that
    /// dig-account confirmed THIS mint rather than some distributor it found.
    ///
    /// # What breaks this test
    ///
    /// Dropping the `submit` call from `begin` (returning a pending built some other way) leaves no
    /// bundle for the publisher to hand back and the `only_bundle` assertion fires; confirming at
    /// `peak` instead of `peak - MIN_CONFIRMATION_DEPTH` leaves the final status `Awaiting`.
    #[test]
    fn begin_drives_a_real_mint_to_awaiting_then_confirmed() {
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

        assert!(
            matches!(
                pending.status(&chain).expect("the mock chain answers"),
                RewardDistributorStatus::Awaiting { .. }
            ),
            "a chain that has not seen the launch reports Awaiting"
        );

        let launcher_id = pending.distributor_launcher_id();
        let confirmed_at = 20;
        let confirmed = confirm_bundle(
            chain,
            &publisher.only_bundle(),
            launcher_id,
            confirmed_at,
            now,
        )
        .with_peak(confirmed_at + MIN_CONFIRMATION_DEPTH);

        match pending.status(&confirmed).expect("the mock chain answers") {
            RewardDistributorStatus::Confirmed(distributor) => assert_eq!(
                distributor.distributor_launcher_id(),
                launcher_id,
                "the settled id must be THIS mint's own predicted distributor"
            ),
            other => panic!("a buried launch must read as Confirmed, got {other:?}"),
        }
    }

    /// (b) A chain read failure during `status` is an `Err`, never a status.
    ///
    /// The distinction the whole confirmation path rests on: `Awaiting` is a claim about the CHAIN
    /// (it was read, and the distributor is not there yet) and `Failed` is a claim that it never
    /// can be. A transport fault supports neither, so it must not be expressible as either -- a
    /// card renders it as *the submission's state is unknown*.
    #[test]
    fn a_chain_read_failure_is_an_error_not_a_status() {
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
            pending.status(&failing_chain),
            Err(MintError::ChainUnreachable(_))
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

    /// A push failure surfaces as `MintError`, not as a pending mint -- `begin` must not report a
    /// pending for a bundle that was never actually pushed, because a pending is the thing a card
    /// then watches and reports on.
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
        assert!(matches!(err, MintError::ChainUnreachable(_)));
    }
}
