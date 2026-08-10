//! The WHOLE-PROFILE mint — a DID singleton **and** the dig-store launched from it — behind seams a
//! build can honestly report on (dig_ecosystem#2398).
//!
//! [`crate::account::chain_mint`] mints a DID and stops there. That is not a profile: a DID is never
//! minted alone, and a user left holding one has spent real XCH for an identity with no store. This
//! module is the door to `dig_account::ProfileMinter`'s three-call ceremony —
//! `begin_profile_mint`, `advance_profile_mint`, `profile_mint_status` — which drives both halves.
//!
//! # Why this sits BESIDE [`ChainMint`](crate::account::chain_mint::ChainMint) rather than replacing it
//!
//! [`DidMinter::submit`](crate::account::mint::DidMinter::submit) takes `&self` and returns one
//! [`Submission`](crate::account::mint::Submission). The profile ceremony is three calls, needs
//! `&mut ProfileRegistry`, and ends in one of FOUR states. Forcing it behind `&self` would mean
//! interior mutability over a registry [`ProfileSession`] already owns behind an `RwLock` — **two
//! owners of the mint journal, which is how a double-spend gets written.** So `DidMinter` and
//! [`MintObserver`](crate::account::mint::MintObserver) are NARROWED to the DID-only wizard they
//! already serve, whose `MintingStep::Possible` unwritability is a proven security property, and the
//! profile ceremony gets its own shape here.
//!
//! `MintObserver::look` is deliberately not extended either: its
//! [`Sighting`](crate::account::mint::Sighting) has three arms and no vocabulary at all for
//! `DidConfirmedStoreNotLaunched` — the one state dig-account itself calls "the state that costs
//! money to get wrong". Collapsing four states into three would lose exactly that one.
//!
//! # What this build can and cannot do, and why the gate has THREE arms
//!
//! Phase B (`launch_store`) re-derives the DID's puzzle material with
//! `dig_did::walk_did_lineage_to_tip`, whose first operation is
//! [`ChainSource::resolve_singleton_lineage`]. [`ControlChainSource`](crate::chain::ControlChainSource)
//! answers that with `Unsupported`, pending the canonical `walk_singleton_lineage` in a forthcoming
//! `dig-chainsource-interface` release
//! (dig_ecosystem#2572). A build in that state can PUSH the DID half and can never finish the store
//! half — every user stranded at `DidConfirmedStoreNotLaunched` with money spent.
//!
//! That is a different fact from having no chain at all, and it has a different remedy, so
//! [`ProfileMintSeams`] names it separately: [`NoLineageWalk`](ProfileMintSeams::NoLineageWalk) is
//! *can start what it cannot finish*, and [`NoChainTransport`](ProfileMintSeams::NoChainTransport)
//! is *cannot reach chain*. Only [`Wired`](ProfileMintSeams::Wired) reports
//! [`ProfileMintAvailability::Possible`].

use std::sync::Arc;

use chia_protocol::Bytes32;
use dig_account::mint::SpendPublisher;
use dig_account::mint::{MintError, MintNetwork, MintOptions, ProfileMintStatus, ProfileSeed};
use dig_account::registry::journal::MintStage;
use dig_chainsource_interface::ChainSource;

use crate::account::active_profile::{MintTarget, WalletSlot};
use crate::account::profile_session::{MintDoorError, PersistOutcome, ProfileSession};
use crate::account::residency::AccountResidency;

/// The launcher id the lineage probe asks about.
///
/// Deliberately a value no singleton can have, so the probe cannot be mistaken for a real read and
/// costs a node nothing to answer. What is under test is whether the call is SERVICED — a source
/// that walks lineages answers `Ok(None)` here, and one that cannot answers `Err`.
const PROBE_LAUNCHER_ID: Bytes32 = Bytes32::new([0; 32]);

/// Whether this build can mint a WHOLE profile — both halves — and, when it cannot, which half is
/// out of reach.
///
/// Distinct from [`MintAvailability`](crate::account::chain_mint::MintAvailability), which answers
/// the narrower DID-only question the first-run wizard asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileMintAvailability {
    /// Both halves are reachable: a mint may be attempted.
    Possible,
    /// Chain reads work and the singleton lineage walk does not, so phase B could never complete.
    /// **Offering a mint here spends real XCH on a profile that can never finish.**
    NoLineageWalk,
    /// No way to read coins or push a bundle at all.
    NoChainTransport,
}

/// The one door a profile mint may be driven through, as a seam a surface can hold.
///
/// A trait so [`ProfileMintSeams`] can carry a mint without naming its chain and publisher types,
/// and so a surface can be tested against a double that cannot spend.
pub trait ProfileMintDoor {
    /// Reserve the index, journal the reservation, and push the DID half.
    ///
    /// # Money
    ///
    /// On mainnet this spends real XCH. The journal entry is written before the push and is KEPT
    /// when the chain cannot be reached, because then the bundle may yet be included.
    fn begin(&self, seed: &ProfileSeed) -> Result<ProfileMintStatus, MintDoorError>;

    /// Drive the mint forward from what the chain now says. Pushes only on evidence.
    fn advance(&self) -> Result<ProfileMintStatus, MintDoorError>;

    /// Where the mint stands, WITHOUT spending, pushing or writing.
    fn status(&self) -> Result<ProfileMintStatus, MintError>;

    /// How alive the in-flight bundle looks, or `None` when no bundle is in flight.
    fn liveness(&self) -> Option<MintLiveness>;
}

/// The profile-minting seams a build actually has — and the ONLY source of a
/// [`ProfileMintAvailability`].
///
/// The availability is READ OFF the seams rather than asserted beside them, for the reason
/// dig_ecosystem#2377 measured on the DID gate: two independent expressions of one capability drift,
/// and the drift ships as a control that offers what the implementation refuses.
pub enum ProfileMintSeams<'a> {
    /// A real mint whose chain source answered a live lineage probe.
    Wired {
        /// The ceremony's door.
        mint: &'a dyn ProfileMintDoor,
    },
    /// The chain answers ordinary reads and refuses the singleton lineage walk.
    ///
    /// Carries the source's own words so a diagnostic names the read that is missing rather than
    /// reporting a generic outage.
    NoLineageWalk {
        /// Why the probe failed, verbatim from the chain source.
        why: Arc<str>,
    },
    /// This build has no chain transport at all.
    NoChainTransport,
}

impl<'a> ProfileMintSeams<'a> {
    /// Decide the seams by ASKING the chain whether it can walk a singleton lineage.
    ///
    /// # This is a runtime probe, and its one weakness is stated rather than hidden
    ///
    /// Only `Ok(_)` is accepted; `Unsupported`, a transport failure and a parse failure all yield
    /// [`NoLineageWalk`](Self::NoLineageWalk). A source that SERVICES the call and answers *wrongly*
    /// would pass — no probe can see that, and the honest walk in
    /// `dig-chainsource-interface` is what will make it moot.
    ///
    /// Every other way to be wrong fails in the SAFE direction: a chain that is merely unreachable
    /// reads as `NoLineageWalk`, which WITHHOLDS the offer. The failure mode this excludes is the
    /// expensive one — offering a mint that strands the user mid-ceremony with money spent.
    ///
    /// # Every walk `Err` is *unknown*, and none of them may become *absent*
    ///
    /// The canonical walk's failures include a timeout, a depth bound and a reveal-size bound, and
    /// it DISCARDS its partial member set on truncation precisely so a membership test cannot fail
    /// open. Mapping any of those to `Ok(None)` would turn *"I could not read the lineage"* into
    /// *"the lineage ends here"*, which on a mint path reads as **safe to spend**. This match makes
    /// that collapse unwritable: only `Ok` is a capability, and every `Err` — whatever its kind —
    /// withholds.
    ///
    /// # What a successful probe does NOT prove
    ///
    /// It proves the SOURCE can service the call. It says nothing about any particular singleton,
    /// and in particular a lineage of exactly `{launcher, eve}` with an unspent eve does **not**
    /// establish that the eve is a genuine singleton curried to that launcher — that rests on the
    /// launcher spender alone. For a DID this host is minting, the launcher spender is this host, so
    /// self-trust covers it. Any future surface resolving a THIRD PARTY's DID from a launcher id
    /// must require a tip beyond the eve, and must not treat this probe as identity verification.
    pub fn probe<C>(mint: &'a dyn ProfileMintDoor, chain: &C) -> Self
    where
        C: ChainSource + ?Sized,
    {
        match chain.resolve_singleton_lineage(PROBE_LAUNCHER_ID) {
            Ok(_) => Self::Wired { mint },
            Err(why) => Self::NoLineageWalk {
                why: why.to_string().into(),
            },
        }
    }

    /// Whether a whole profile can be minted here — derived from the seams, never asserted beside
    /// them.
    pub fn availability(&self) -> ProfileMintAvailability {
        match self {
            Self::Wired { .. } => ProfileMintAvailability::Possible,
            Self::NoLineageWalk { .. } => ProfileMintAvailability::NoLineageWalk,
            Self::NoChainTransport => ProfileMintAvailability::NoChainTransport,
        }
    }

    /// The mint door, or `None` on a build that has none.
    ///
    /// `None` rather than a refusing stand-in: a profile mint has no honest no-op, because "begin"
    /// on a build that cannot finish is the very thing these seams exist to prevent.
    pub fn door(&self) -> Option<&'a dyn ProfileMintDoor> {
        match self {
            Self::Wired { mint } => Some(*mint),
            Self::NoLineageWalk { .. } | Self::NoChainTransport => None,
        }
    }
}

/// How alive an in-flight mint bundle looks.
///
/// # dig-app NEVER auto-declares a mint dead, and the arms are shaped to make that impossible
///
/// The two ways to be wrong are not symmetric. Wrong-permissive costs a user patience. Wrong-
/// aggressive tells them their mint failed, they mint again, the original confirms, and they have
/// paid twice and own an orphan DID. No timeout threshold is worth that, so there is no threshold
/// here at all: [`Waiting`](Self::Waiting) REPORTS elapsed blocks and asserts nothing about them
/// (dig_ecosystem#2351).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintLiveness {
    /// The bundle has not been seen on chain yet. The number is a measurement, not a verdict.
    Waiting {
        /// Blocks between the peak at push time and the peak now.
        blocks_since_push: u32,
    },
    /// The chain PROVES this bundle can never confirm: the coin it spends is already spent, by some
    /// other spend, and the coin this mint would have created does not exist.
    ProvablyDead {
        /// What the chain showed.
        evidence: DeathEvidence,
    },
    /// The chain could not answer. **Not dead, and not waiting** — an unreachable node says nothing
    /// at all about a bundle, and an arm that folded this into either would put a network outage in
    /// front of a user as a fact about their money.
    Unknown,
}

/// Why a mint is provably dead: its funding coin went somewhere else.
///
/// Both halves are required. A spent funding coin ALONE is what a SUCCESSFUL mint looks like — the
/// bundle spends it — so death is only proven when the coin is gone AND the coin this mint would
/// have created was never created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeathEvidence {
    /// The wallet coin the mint bundle spends.
    pub funding_coin_id: Bytes32,
    /// The height at which some OTHER spend consumed it.
    pub funding_spent_at: u32,
    /// The DID coin the bundle would have created, which the chain does not have.
    pub absent_did_coin_id: Bytes32,
}

/// Read the liveness of the mint journalled at `ix`.
///
/// `None` means no bundle is in flight at all — either nothing is journalled there, or the mint is
/// paused at `DidConfirmedStoreNotLaunched`, where nothing is waiting on the network.
///
/// # Why the death test needs `coin_record` by COIN ID
///
/// `control.wallet.coins` is address-scoped and unspent-only, so it structurally cannot see a coin
/// that has already been spent. `coin_record` maps to `control.wallet.coinById`, which answers about
/// spent coins — which is what makes [`MintLiveness::ProvablyDead`] observable at all rather than a
/// timeout dressed up as evidence.
pub fn liveness_of<C>(
    session: &ProfileSession,
    ix: dig_account::ProfileIx,
    chain: &C,
) -> Option<MintLiveness>
where
    C: ChainSource + ?Sized,
{
    let in_flight = session.with_registry(|registry| {
        registry
            .in_progress()
            .iter()
            .find(|mint| mint.ix() == ix)
            .and_then(|mint| match mint.stage() {
                MintStage::DidPushed { pending } => Some(InFlight {
                    funding_coin_id: pending.source_coin_id,
                    created_coin_id: pending.did_coin_id,
                    pushed_at_height: pending.pushed_at_height,
                }),
                MintStage::StorePushed { pending_store, .. } => Some(InFlight {
                    funding_coin_id: pending_store.did_coin_id,
                    created_coin_id: pending_store.store_coin_id,
                    pushed_at_height: pending_store.pushed_at_height,
                }),
                // The DID exists and no bundle is on the network: this is a mint waiting on THIS
                // host to act, not on the chain, so it has no liveness to report.
                MintStage::DidConfirmedStoreNotLaunched { .. } => None,
            })
    })?;

    Some(in_flight.read(chain))
}

/// The three coin facts every in-flight stage has, whichever half is in the air.
struct InFlight {
    /// The coin the bundle consumes.
    funding_coin_id: Bytes32,
    /// The coin the bundle would create.
    created_coin_id: Bytes32,
    /// The chain's peak immediately before the push.
    pushed_at_height: u32,
}

impl InFlight {
    /// Ask the chain, and answer only what it proves.
    fn read<C>(&self, chain: &C) -> MintLiveness
    where
        C: ChainSource + ?Sized,
    {
        let (Ok(Some(peak)), Ok(created), Ok(funding)) = (
            chain.peak_height(),
            chain.coin_record(self.created_coin_id),
            chain.coin_record(self.funding_coin_id),
        ) else {
            return MintLiveness::Unknown;
        };

        // The coin this bundle creates EXISTS, so the bundle was included. Nothing to declare.
        if created.is_some() {
            return MintLiveness::Waiting {
                blocks_since_push: peak.saturating_sub(self.pushed_at_height),
            };
        }

        // The funding coin is gone and the coin it should have created never appeared: some other
        // spend consumed it, and this bundle can never be included.
        if let Some(spent_at) = funding.and_then(|record| record.spent_height) {
            return MintLiveness::ProvablyDead {
                evidence: DeathEvidence {
                    funding_coin_id: self.funding_coin_id,
                    funding_spent_at: spent_at,
                    absent_did_coin_id: self.created_coin_id,
                },
            };
        }

        MintLiveness::Waiting {
            blocks_since_push: peak.saturating_sub(self.pushed_at_height),
        }
    }
}

/// Mints a whole profile through dig-account, journalling every step through [`ProfileSession`].
///
/// # Ownership
///
/// It holds a `&ProfileSession`, **never a registry**. The session is the registry's sole owner, and
/// a second owner of the mint journal is how a double-spend gets written.
///
/// # The restart-surviving guarantee this gains over [`ChainMint`](crate::account::chain_mint::ChainMint)
///
/// `ChainMint` refuses a second push from a `Mutex<Option<PendingMint>>`, which lives exactly as
/// long as the process: closing and reopening dig-app resets it and permits a second paid mint. Here
/// the refusal is `ProfileRegistry::begin_seeded_mint` declining a reserved index, and the registry
/// is PERSISTED — so the guard **survives a restart**.
pub struct ProfileMint<'a, C: ?Sized, P: ?Sized> {
    /// The registry's owner, and the only thing that writes the journal.
    session: &'a ProfileSession,
    /// The live account. A `ProfileMinter` is derived per call and never retained, so a mint
    /// attempted after a lock cannot even be built.
    residency: &'a AccountResidency,
    /// The profile whose wallet PAYS.
    funding: WalletSlot,
    /// The index the new profile derives at.
    target: MintTarget,
    /// Reads coins, spends and the peak. Cannot broadcast, by construction.
    chain: &'a C,
    /// Pushes the signed bundle. Never sees a key.
    publisher: &'a P,
    /// Which network's `AGG_SIG_ME` domain the mint signs under.
    network: MintNetwork,
    /// The farmer fee PER BUNDLE, bounded by dig-account's `MAX_MINT_FEE_MOJOS` ceiling.
    options: MintOptions,
}

impl<'a, C, P> ProfileMint<'a, C, P>
where
    C: ChainSource + ?Sized,
    P: SpendPublisher + ?Sized,
{
    /// A profile mint paying from `funding`'s wallet and creating the profile at `target`.
    ///
    /// # Money
    ///
    /// With [`MintNetwork::mainnet`] this spends real XCH the moment [`ProfileMintDoor::begin`] is
    /// called. `options.fee` is charged **per bundle** and a whole profile is two bundles, so the
    /// total a user pays is twice the fee plus two singleton mojos.
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authority, and the two that move money \
                  (`publisher`, `options`) must stay visible at the call site"
    )]
    pub fn new(
        session: &'a ProfileSession,
        residency: &'a AccountResidency,
        funding: WalletSlot,
        target: MintTarget,
        chain: &'a C,
        publisher: &'a P,
        network: MintNetwork,
        options: MintOptions,
    ) -> Self {
        Self {
            session,
            residency,
            funding,
            target,
            chain,
            publisher,
            network,
            options,
        }
    }

    /// The total a whole profile costs, in mojos: two bundles' fees plus the two singleton mojos.
    ///
    /// Derived from the SAME [`MintOptions`] the mint is charged under, so a displayed cost cannot
    /// come to be lower than what is spent.
    pub fn cost_mojos(&self) -> u64 {
        const SINGLETON_MOJOS_PER_HALF: u64 = 1;
        self.options
            .fee
            .saturating_add(SINGLETON_MOJOS_PER_HALF)
            .saturating_mul(2)
    }

    /// dig-account's minter, derived fresh.
    ///
    /// **Derived before any registry lock is taken**, deliberately: this touches the account mutex,
    /// and [`ProfileSession`]'s lock-ordering rule forbids taking that mutex while a registry guard
    /// is held.
    fn minter(&self) -> Result<dig_account::ProfileMinter, MintError> {
        self.residency.profile_minter().ok_or(MintError::Locked)
    }

    /// Refuse a mint that would pay from one profile and create another.
    ///
    /// dig-account's ceremony mints at an index AND funds from that same index's wallet, so it
    /// cannot express the divergent case: passing the target would spend from a brand-new profile's
    /// empty wallet, and passing the funding index would mint at the wrong one. Carried over from
    /// [`ChainMint`](crate::account::chain_mint::ChainMint) verbatim (dig_ecosystem#2496).
    fn refuse_divergent_indices(&self) -> Result<(), MintError> {
        if self.funding.ix() == self.target.ix() {
            return Ok(());
        }
        Err(MintError::Refused(format!(
            "This mint would pay from profile {} but create profile {}, and DIG cannot yet fund \
             one profile's mint from another's wallet. Move funds to profile {}'s address first.",
            self.funding, self.target, self.target
        )))
    }
}

impl<C, P> ProfileMintDoor for ProfileMint<'_, C, P>
where
    C: ChainSource + Sized,
    P: SpendPublisher + ?Sized,
{
    fn begin(&self, seed: &ProfileSeed) -> Result<ProfileMintStatus, MintDoorError> {
        let prepared = self.refuse_divergent_indices().and_then(|()| self.minter());
        let minter = match prepared {
            Ok(minter) => minter,
            // Nothing was journalled and nothing was pushed, so there is nothing to persist.
            Err(mint) => {
                return Err(MintDoorError {
                    mint: Some(mint),
                    persisted: PersistOutcome::Written,
                })
            }
        };

        self.session.with_journal(|registry| {
            minter.begin_profile_mint(
                registry,
                self.target.ix(),
                seed,
                self.chain,
                self.publisher,
                &self.network,
                &self.options,
            )
        })
    }

    fn advance(&self) -> Result<ProfileMintStatus, MintDoorError> {
        let minter = match self.minter() {
            Ok(minter) => minter,
            Err(mint) => {
                return Err(MintDoorError {
                    mint: Some(mint),
                    persisted: PersistOutcome::Written,
                })
            }
        };

        self.session.with_journal(|registry| {
            minter.advance_profile_mint(
                registry,
                self.target.ix(),
                self.chain,
                self.publisher,
                &self.network,
            )
        })
    }

    fn status(&self) -> Result<ProfileMintStatus, MintError> {
        // `&self` over a `&`-registry: there is no argument that makes this move money, which is
        // what lets a "Check again" control exist in the waiting state at all.
        let minter = self.minter()?;
        self.session.with_registry(|registry| {
            minter.profile_mint_status(registry, self.target.ix(), self.chain)
        })
    }

    fn liveness(&self) -> Option<MintLiveness> {
        liveness_of(self.session, self.target.ix(), self.chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_chainsource_interface::{
        ChainSourceError, CoinRecord, MockChainSource, SingletonLineage,
    };

    /// A plausible mainnet height, so nothing passes because the numbers are small.
    const PEAK: u32 = 5_412_009;

    /// The height a mint was pushed at, far enough below [`PEAK`] that any plausible "is it dead
    /// yet" threshold would already have fired. That gap is what makes the no-threshold rule
    /// testable rather than merely stated.
    const PUSHED_AT: u32 = PEAK - 20_000;

    fn coin_id(tag: u8) -> Bytes32 {
        Bytes32::new([tag; 32])
    }

    /// A confirmed, UNSPENT record.
    fn unspent(id: Bytes32) -> CoinRecord {
        CoinRecord {
            coin: chia_protocol::Coin::new(coin_id(0xEE), id, 1),
            confirmed_height: Some(PUSHED_AT - 10),
            spent_height: None,
            timestamp: None,
            coinbase: false,
        }
    }

    /// The same record, consumed at `height`.
    fn spent_at(id: Bytes32, height: u32) -> CoinRecord {
        CoinRecord {
            spent_height: Some(height),
            ..unspent(id)
        }
    }

    /// A chain source that ANSWERS the lineage walk — the control every probe test needs.
    struct WalksLineages;

    impl ChainSource for WalksLineages {
        type Error = String;
        fn coin_record(&self, _id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            Ok(None)
        }
        fn coin_records_by_puzzle_hash(
            &self,
            _ph: Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(Vec::new())
        }
        fn coin_records_by_parent(&self, _p: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(Vec::new())
        }
        fn coin_spend(
            &self,
            _id: Bytes32,
        ) -> Result<Option<chia_protocol::CoinSpend>, Self::Error> {
            Ok(None)
        }
        fn resolve_singleton_lineage(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<SingletonLineage>, Self::Error> {
            // `Ok(None)` — the probe's launcher id names no singleton, and answering that IS the
            // capability under test.
            Ok(None)
        }
        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            Ok(Some(PEAK))
        }
        fn block_timestamp(&self, _h: u32) -> Result<Option<u64>, Self::Error> {
            Ok(None)
        }
    }

    /// A mint door that records whether anything asked it to spend.
    #[derive(Default)]
    struct CountingDoor {
        begins: std::cell::Cell<usize>,
    }

    impl ProfileMintDoor for CountingDoor {
        fn begin(&self, _seed: &ProfileSeed) -> Result<ProfileMintStatus, MintDoorError> {
            self.begins.set(self.begins.get() + 1);
            Ok(ProfileMintStatus::DidPending {
                did_coin_id: coin_id(1),
            })
        }
        fn advance(&self) -> Result<ProfileMintStatus, MintDoorError> {
            Ok(ProfileMintStatus::DidPending {
                did_coin_id: coin_id(1),
            })
        }
        fn status(&self) -> Result<ProfileMintStatus, MintError> {
            Ok(ProfileMintStatus::DidPending {
                did_coin_id: coin_id(1),
            })
        }
        fn liveness(&self) -> Option<MintLiveness> {
            None
        }
    }

    /// **A chain that refuses the lineage walk yields a non-`Possible` availability, and NOTHING
    /// asks the door to spend.**
    ///
    /// Makes impossible: a build shipping a profile-create offer against a source that cannot finish
    /// phase B — the arrangement that strands a user at `DidConfirmedStoreNotLaunched` with money
    /// spent.
    ///
    /// The control leg is what makes it load-bearing. With only the refusing source, a `probe()`
    /// hardcoded to return `NoLineageWalk` would pass identically; the second half varies ONE thing
    /// — a source that answers the walk — and requires a real `Possible` out of the same function.
    #[test]
    fn a_source_that_cannot_walk_a_lineage_is_not_offered_a_mint() {
        let door = CountingDoor::default();
        let refuses = MockChainSource::new()
            .with_peak(PEAK)
            .fail_with(ChainSourceError::Unsupported("no lineage walk here".into()));

        let seams = ProfileMintSeams::probe(&door, &refuses);

        assert_eq!(seams.availability(), ProfileMintAvailability::NoLineageWalk);
        assert!(
            seams.door().is_none(),
            "a build that cannot finish phase B must have no door to begin one"
        );
        assert_eq!(
            door.begins.get(),
            0,
            "a withheld offer must not have reached the mint at all"
        );

        // Control: the SAME door, a source that answers the walk.
        let wired = ProfileMintSeams::probe(&door, &WalksLineages);
        assert_eq!(wired.availability(), ProfileMintAvailability::Possible);
        assert!(
            wired.door().is_some(),
            "the control must genuinely be offered, or the refusal above proves nothing"
        );
    }

    /// **The availability and the obtainable door cannot disagree, in EITHER direction.**
    ///
    /// Makes impossible: the dig_ecosystem#2377 defect, where the gate lived in one expression and
    /// the capability in another, so a one-line edit to the gate opened a dead end. Asserted over
    /// all three arms so neither "always `Some`" nor "always `None`" survives.
    #[test]
    fn availability_and_the_door_agree_on_every_arm() {
        let door = CountingDoor::default();
        let refusing = MockChainSource::new()
            .with_peak(PEAK)
            .fail_with(ChainSourceError::Unsupported("nope".into()));

        for seams in [
            ProfileMintSeams::probe(&door, &WalksLineages),
            ProfileMintSeams::probe(&door, &refusing),
            ProfileMintSeams::NoChainTransport,
        ] {
            let possible = seams.availability() == ProfileMintAvailability::Possible;
            assert_eq!(
                possible,
                seams.door().is_some(),
                "a {:?} build must offer a door exactly when it reports Possible",
                seams.availability()
            );
        }
    }

    /// **An unreachable chain is `Unknown` — never `ProvablyDead` and never `Waiting`.**
    ///
    /// Makes impossible: a network outage rendered to a user as a fact about their money. The
    /// control leg supplies the SAME journalled mint against a chain that answers, so an
    /// implementation that returned `Unknown` unconditionally cannot pass.
    #[test]
    fn a_chain_that_cannot_answer_is_unknown_rather_than_dead() {
        let flight = InFlight {
            funding_coin_id: coin_id(2),
            created_coin_id: coin_id(3),
            pushed_at_height: PUSHED_AT,
        };

        let down = MockChainSource::new()
            .with_peak(PEAK)
            .fail_with(ChainSourceError::Transport("the network is down".into()));
        assert_eq!(flight.read(&down), MintLiveness::Unknown);

        // Control: the same mint, a chain that answers — a real, non-Unknown reading.
        let up = MockChainSource::new()
            .with_peak(PEAK)
            .with_coin(coin_id(2), unspent(coin_id(2)));
        assert_eq!(
            flight.read(&up),
            MintLiveness::Waiting {
                blocks_since_push: 20_000
            }
        );
    }

    /// **A mint pushed long ago and never confirmed stays `Waiting` — dig-app declares no timeout.**
    ///
    /// Makes impossible: an elapsed-blocks threshold that reports a live mint as failed, after which
    /// a user re-mints, the original confirms, and they have paid twice and own an orphan DID.
    ///
    /// The fixture is 20,000 blocks past the push — roughly six weeks of Chia blocks, far beyond any
    /// threshold anybody would write — with the funding coin still UNSPENT, which is precisely the
    /// shape a stuck-but-alive bundle has. A fixture only a few blocks old could not tell a
    /// no-threshold implementation from a generous one.
    #[test]
    fn a_long_unconfirmed_mint_is_still_waiting_and_never_declared_dead() {
        let flight = InFlight {
            funding_coin_id: coin_id(2),
            created_coin_id: coin_id(3),
            pushed_at_height: PUSHED_AT,
        };
        let chain = MockChainSource::new()
            .with_peak(PEAK)
            .with_coin(coin_id(2), unspent(coin_id(2)));

        assert_eq!(
            flight.read(&chain),
            MintLiveness::Waiting {
                blocks_since_push: 20_000
            },
            "elapsed blocks are REPORTED; no number of them is a verdict"
        );
    }

    /// **A funding coin consumed by another spend, with the mint's own coin absent, is
    /// `ProvablyDead` — and that is the ONLY way to reach that arm.**
    ///
    /// Makes impossible: inferring death from elapsed time. The evidence names the coin and the
    /// height, so a surface can show what the chain showed.
    ///
    /// The second leg is the one that keeps this honest: the SAME spent funding coin, with the DID
    /// coin PRESENT, is a mint that SUCCEEDED — a bundle spends its own funding coin. An
    /// implementation testing only `spent_height.is_some()` would call every completed mint dead.
    #[test]
    fn a_spent_funding_coin_is_death_only_when_the_mint_created_nothing() {
        let flight = InFlight {
            funding_coin_id: coin_id(2),
            created_coin_id: coin_id(3),
            pushed_at_height: PUSHED_AT,
        };
        let stolen = MockChainSource::new()
            .with_peak(PEAK)
            .with_coin(coin_id(2), spent_at(coin_id(2), PUSHED_AT + 3));

        assert_eq!(
            flight.read(&stolen),
            MintLiveness::ProvablyDead {
                evidence: DeathEvidence {
                    funding_coin_id: coin_id(2),
                    funding_spent_at: PUSHED_AT + 3,
                    absent_did_coin_id: coin_id(3),
                }
            }
        );

        // The successful mint: the same coin spent, and the coin it created EXISTS.
        let succeeded = MockChainSource::new()
            .with_peak(PEAK)
            .with_coin(coin_id(2), spent_at(coin_id(2), PUSHED_AT + 3))
            .with_coin(coin_id(3), unspent(coin_id(3)));
        assert_eq!(
            succeeded_reading(&flight, &succeeded),
            MintLiveness::Waiting {
                blocks_since_push: 20_000
            },
            "a bundle spends its own funding coin — that alone can never mean death"
        );
    }

    /// Named so the assertion above reads as the claim it makes rather than as a second `read`.
    fn succeeded_reading<C: ChainSource + ?Sized>(flight: &InFlight, chain: &C) -> MintLiveness {
        flight.read(chain)
    }
}
