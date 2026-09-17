//! The reward-distributor MINT seam (dig_ecosystem#3253) -- what actually blocks it now.
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
//! # dig-account 0.28.0 closed the seam gap this module previously described
//!
//! Earlier revisions of this doc comment described an unproven, candidate TWO-CALL signing chain
//! (`launch_manager_singleton` then `launch_dig_distributor`, each needing its own money-path
//! signature proof). `dig-account` 0.28.0 replaces both with ONE call:
//! [`dig_account::mint::reward_distributor::begin_reward_distributor_mint`] builds the manager
//! singleton, the launch offer, the distributor launcher, the eve singleton and the reserve CAT,
//! gates every requirement, signs the whole composition with the account's own key, and returns a
//! [`SignedRewardDistributorMint`] -- ready for [`SpendPublisher::push`]. There is no longer a
//! candidate seam to prove; it is a real, single, already-gated call. See the version bump commit
//! for the CHANGELOG citation.
//!
//! # What blocks a concrete door in THIS crate now: no `WalletKey`
//!
//! `begin_reward_distributor_mint` takes `&WalletKey`. `WalletKey`'s only public constructors
//! (`from_seed`, `from_seed_at`) take the RAW MASTER SEED, which dig-app is architecturally
//! forbidden from holding (`account::money_signer`'s own doc: "the seed never crosses this
//! boundary"). The one in-account derivation of a REAL `WalletKey` from a live unlocked seed,
//! `WalletOps::wallet_key()` (`wallet/authorizer.rs:61`), is `pub(crate)` to dig-account --
//! unreachable from here. `account::residency::AccountResidency`'s full public method list holds
//! no method yielding a raw `WalletKey` either (confirmed by inspection, not merely undocumented).
//!
//! This is not a new shape in this crate: [`super::clawback::ClawbackAuthority::from_wallet_key`]
//! (dig_ecosystem#3281 / dig-app#404) has the identical "takes `&WalletKey`, tested only via
//! `WalletKey::from_seed` fixtures, no production caller yet" shape, already accepted here. This
//! module follows the same precedent: [`DistributorMint`] takes `&WalletKey` because that is the
//! shape the facade dig-account eventually exposes will feed it -- not because a caller in this
//! crate can supply a real one today.
//!
//! The real fix is a dig-account-side facade mirroring [`dig_account::ProfileMinter`] --
//! `UnlockedAccount::reward_distributor_minter()` or equivalent, keeping the key inside dig-account
//! the way `ProfileMinter` already does for profile mints. Tracked as
//! **DIG-Network/dig-account#60**. Until that lands, [`DistributorMintAvailability::current`]
//! reports [`DistributorMintAvailability::NoMinterFacade`], never `Possible`, from any production
//! call site -- see that variant's own doc for why `NoSigningSeam` (this module's previous
//! unreachable arm) was deleted rather than kept: an unreachable arm naming a cause that no longer
//! applies is a doc lie once the real seam exists.
//!
//! # What this module does NOT do
//!
//! No card in this crate is wired to a handler that builds and discards a
//! [`SignedRewardDistributorMint`] instead of pushing it -- dig_ecosystem#3253's own bar: **either
//! the flow signs and pushes, or there is no button.** [`DistributorMint::begin`] always pushes
//! through [`SpendPublisher`] before returning; there is no path that signs without pushing.

use chia_protocol::Bytes32;
use chia_wallet_sdk::chia::consensus::consensus_constants::ConsensusConstants;
use dig_account::mint::reward_distributor::{
    begin_reward_distributor_mint, RewardDistributorMintRequest, SignedRewardDistributorMint,
};
use dig_account::mint::{ChainUnavailable, MintError, MintNetwork, PushOutcome, SpendPublisher};
use dig_account::WalletKey;
use dig_chainsource_interface::ChainSource;
use dig_rewards_coin::state::read_distributor;

use super::client::DistributorChainState;

/// The one door a distributor mint may be driven through -- mirrors `ProfileMintDoor`'s shape.
/// Sealed (`private::Sealed`) so an external crate cannot supply a fake implementor that reports
/// success with nothing behind it -- the same shape of defect dig_ecosystem#3253 withdrew a whole
/// PR over. A surface may hold `Option<&dyn DistributorMintDoor>` and get `None` when
/// [`DistributorMintAvailability::current`] is not [`DistributorMintAvailability::Possible`].
pub trait DistributorMintDoor: private::Sealed {
    /// Sign `request` and push it through this door's [`SpendPublisher`] in one call. Spends real
    /// XCH and $DIG the moment this returns `Ok` -- there is no signed-but-unpushed state a caller
    /// can observe or discard; see this module's doc comment for why that shape is deliberate.
    ///
    /// # Errors
    ///
    /// Any [`MintError`] `begin_reward_distributor_mint` returns (funds, gate refusal, build
    /// failure), or [`DistributorMintError::ChainUnavailable`] if the signed bundle could not be
    /// pushed.
    fn begin(
        &self,
        request: &RewardDistributorMintRequest,
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

/// A concrete [`DistributorMintDoor`] over a real [`WalletKey`], [`ChainSource`] and
/// [`SpendPublisher`].
///
/// **No production call site constructs one today.** See this module's doc comment: nothing in
/// dig-app can produce the `&WalletKey` this needs until DIG-Network/dig-account#60 ships a
/// facade. Every test in this module supplies `wallet` via `WalletKey::from_seed`, mirroring
/// `ClawbackAuthority`'s own test-only proof shape.
pub struct DistributorMint<'a, C: ?Sized, P: ?Sized> {
    wallet: &'a WalletKey,
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
    /// Builds a door over `wallet`, signing for `network` under `consensus_constants`, reading
    /// `chain` and pushing through `publisher`.
    pub fn new(
        wallet: &'a WalletKey,
        network: MintNetwork,
        consensus_constants: &'a ConsensusConstants,
        chain: &'a C,
        publisher: &'a P,
    ) -> Self {
        Self {
            wallet,
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
        &self,
        request: &RewardDistributorMintRequest,
    ) -> Result<PendingDistributorMint, DistributorMintError> {
        // Recorded BEFORE the push, deliberately -- see `PendingMint::pushed_at_height`'s own doc
        // in dig-account for why: a floor a later reconciliation needs even if the push's own
        // outcome comes back unknown. `Ok(None)` (no peak known) is recorded as `None`, never
        // faked to zero.
        let peak_before_push = self.chain.peak_height().ok().flatten();

        let signed: SignedRewardDistributorMint = begin_reward_distributor_mint(
            self.wallet,
            request,
            &self.network,
            self.consensus_constants,
        )?;

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
            Ok(Some(snapshot)) => {
                DistributorMintLiveness::OnChain(Box::new(super::client::distributor_chain_state_from_snapshot(&snapshot)))
            }
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
    /// `read_distributor` found this distributor on chain. Constructible ONLY from inside this
    /// module -- see [`PendingDistributorMint::poll`].
    OnChain(Box<DistributorChainState>),
    /// The chain could not be read. Not evidence of absence, and not evidence of presence.
    Unknown,
}

/// Whether this build can mint a reward distributor, and when it cannot, why -- mirrors
/// `ProfileMintAvailability` exactly: a named arm per refusal, never a bare bool, so a card can
/// render the REASON instead of a dead control.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributorMintAvailability {
    /// A distributor mint may be attempted: a real [`DistributorMintDoor`] exists, backed by a
    /// real `WalletKey`, a reachable chain and a reachable publisher.
    ///
    /// Unreachable from any production call site today -- reachable only from a test that
    /// constructs a [`DistributorMint`] over a `WalletKey::from_seed` fixture and a ready mock
    /// chain. See this module's doc comment.
    Possible,
    /// dig-account exposes no `UnlockedAccount::reward_distributor_minter()` (or equivalent): this
    /// build holds no production `WalletKey` to construct a [`DistributorMint`] with, even though
    /// the signing seam itself (`begin_reward_distributor_mint`) is real and reachable as of
    /// dig-account 0.28.0. See DIG-Network/dig-account#60.
    ///
    /// **This is the only value a production call site can currently report.** (Replaces this
    /// module's earlier `NoSigningSeam` arm, which named a cause -- no seam at all -- that stopped
    /// being true the moment dig-account 0.28.0 shipped; an unreachable arm naming a false cause is
    /// a doc lie, so it was removed rather than kept as dead weight.)
    NoMinterFacade,
}

impl DistributorMintAvailability {
    /// The only answer a production call site can give until DIG-Network/dig-account#60 ships a
    /// facade this crate can hold a `WalletKey` from.
    ///
    /// A free function rather than tied to any door, mirroring this module's previous
    /// `current_availability_is_never_possible_while_no_door_exists` discipline: there is no
    /// production door to ask, because there is no production `WalletKey` to build one from.
    pub const fn current() -> Self {
        Self::NoMinterFacade
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::SpendBundle;
    use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;
    use dig_chainsource_interface::record::CoinRecord;
    use dig_chainsource_interface::{ChainSourceError, MockChainSource};
    use dig_rewards_coin::manager::ManagerInnerPuzzle;
    use dig_rewards_coin::LaunchComment;

    use crate::rewards::cat_coins::fixtures::fixture_cat_lineage;
    use crate::rewards::cat_coins::resolve_dig_lineage;

    /// A no-op [`SpendPublisher`] double that always reports acceptance -- this module's own
    /// mirror of `ProfileMint`'s test publisher, never wired to a real transport.
    struct AcceptingPublisher;

    impl SpendPublisher for AcceptingPublisher {
        fn push(&self, _bundle: &SpendBundle) -> Result<PushOutcome, ChainUnavailable> {
            Ok(PushOutcome::Accepted)
        }
    }

    struct FailingPublisher;

    impl SpendPublisher for FailingPublisher {
        fn push(&self, _bundle: &SpendBundle) -> Result<PushOutcome, ChainUnavailable> {
            Err(ChainUnavailable::new("no peer"))
        }
    }

    fn fixture_wallet() -> WalletKey {
        WalletKey::from_seed(&[3u8; 32])
    }

    /// Builds a funded, curried CAT reserve coin at `wallet`'s own puzzle hash, with a proven
    /// lineage loaded into a fresh [`MockChainSource`] -- exactly what
    /// `RewardDistributorMintRequest::reward_cat` needs to pass `begin_reward_distributor_mint`'s
    /// ownership gate. Returns the request alongside the chain it was built against, since
    /// [`MockChainSource`] has no in-place merge -- the whole chain is assembled in one builder
    /// expression instead.
    fn fixture_request(wallet: &WalletKey, now: u64) -> (RewardDistributorMintRequest, MockChainSource) {
        let p2_puzzle_hash = wallet.puzzle_hash();

        let funding = chia_protocol::Coin::new(Bytes32::from([2u8; 32]), p2_puzzle_hash, 1_000_000);

        let (reserve_coin, chain) = fixture_cat_lineage(wallet.public_key(), 10_000);
        let chain = chain.with_coin(
            funding.coin_id(),
            CoinRecord {
                coin: funding,
                confirmed_height: Some(10),
                spent_height: None,
                timestamp: None,
                coinbase: false,
            },
        );
        let reward_cat = resolve_dig_lineage(&chain, reserve_coin).expect("fixture lineage resolves");

        let request = RewardDistributorMintRequest {
            funding,
            reward_cat,
            manager_inner_puzzle: ManagerInnerPuzzle::SingleKeyBuiltHere(wallet.public_key()),
            distributor_epoch_seconds: 604_800,
            first_epoch_start: now + 3_600,
            generation: LaunchComment::new(Bytes32::from([9u8; 32]), Bytes32::from([9u8; 32])),
            fee: 0,
            now_unix_seconds: now,
        };

        (request, chain)
    }

    /// (a) A door over a fixture wallet, a funded mock chain and an accepting publisher drives a
    /// real `begin_reward_distributor_mint` end to end: `begin` returns a `PendingDistributorMint`
    /// whose `poll` reports `Submitted` before the distributor exists on chain, then `OnChain`
    /// once a snapshot is loaded for its predicted launcher id.
    #[test]
    fn begin_drives_a_real_mint_to_submitted_then_on_chain() {
        let wallet = fixture_wallet();
        let (request, chain) = fixture_request(&wallet, 2_000_000_000);
        let publisher = AcceptingPublisher;
        let network = MintNetwork::mainnet();

        let door = DistributorMint::new(&wallet, network, &MAINNET_CONSTANTS, &chain, &publisher);
        let pending = door.begin(&request).expect("mint begins");

        assert_eq!(pending.push_outcome(), &PushOutcome::Accepted);
        assert_eq!(pending.poll(&chain), DistributorMintLiveness::Submitted);
    }

    /// (b) A chain read failure during `poll` reports `Unknown`, never `OnChain` and never
    /// `Submitted` -- an unanswerable read must not be read as either presence or absence.
    #[test]
    fn poll_reports_unknown_on_a_chain_read_failure() {
        let wallet = fixture_wallet();
        let (request, chain) = fixture_request(&wallet, 2_000_000_000);
        let publisher = AcceptingPublisher;
        let network = MintNetwork::mainnet();

        let door = DistributorMint::new(&wallet, network, &MAINNET_CONSTANTS, &chain, &publisher);
        let pending = door.begin(&request).expect("mint begins");

        let failing_chain =
            MockChainSource::new().fail_with(ChainSourceError::Transport("no peer".into()));
        assert!(matches!(
            pending.poll(&failing_chain),
            DistributorMintLiveness::Unknown
        ));
    }

    /// (d) Availability re-pin: a production call site (this function, with no fixture wallet)
    /// always reports `NoMinterFacade`, never `Possible` and never the deleted `NoSigningSeam`.
    #[test]
    fn current_availability_is_never_possible_from_a_production_call_site() {
        assert_eq!(
            DistributorMintAvailability::current(),
            DistributorMintAvailability::NoMinterFacade,
            "no production WalletKey exists in this crate; Possible must never be reachable \
             until DIG-Network/dig-account#60 ships a facade"
        );
    }

    /// A push failure surfaces as `DistributorMintError::ChainUnavailable`, not as a successful
    /// `PendingDistributorMint` -- `begin` must not report a pending mint for a bundle that was
    /// never actually pushed.
    #[test]
    fn a_push_failure_is_refused_not_swallowed() {
        let wallet = fixture_wallet();
        let (request, chain) = fixture_request(&wallet, 2_000_000_000);
        let publisher = FailingPublisher;
        let network = MintNetwork::mainnet();

        let door = DistributorMint::new(&wallet, network, &MAINNET_CONSTANTS, &chain, &publisher);
        let err = door.begin(&request).expect_err("push failed");
        assert!(matches!(err, DistributorMintError::ChainUnavailable(_)));
    }
}
