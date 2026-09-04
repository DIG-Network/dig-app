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
//! [`ChainSource::resolve_singleton_lineage`].
//! [`ControlChainSource`](crate::chain::ControlChainSource) now SERVES that read, by delegating to
//! `dig_chainsource_interface`'s one hardened `walk_singleton_lineage` (dig_ecosystem#2572), so a
//! whole profile can be minted on a build whose node answers.
//!
//! It is still not a given. A node that is not running cannot be reached at all, and a node too old
//! to serve the two source methods the walk composes cannot walk one — and those are DIFFERENT facts with
//! different remedies (*start your node* versus *upgrade*). So [`ProfileMintSeams`] keeps them
//! apart: [`NoLineageWalk`](ProfileMintSeams::NoLineageWalk) is *reached the chain, cannot finish a
//! mint*, and [`NoChainTransport`](ProfileMintSeams::NoChainTransport) is *could not reach the chain
//! at all*. Only [`Wired`](ProfileMintSeams::Wired) reports
//! [`ProfileMintAvailability::Possible`], and a build that cannot finish phase B must never offer a
//! mint: the user would spend real XCH and be stranded at `DidConfirmedStoreNotLaunched`.

use std::sync::Arc;

use chia_protocol::Bytes32;
use dig_account::mint::SpendPublisher;
use dig_account::mint::{
    ConfirmedStore, MintError, MintNetwork, MintOptions, MintedDid, ProfileMintStatus, ProfileSeed,
};
use dig_account::registry::journal::MintStage;
use dig_account::ProfileIx;
use dig_chainsource_interface::ChainSource;

use crate::account::active_profile::{MintTarget, WalletSlot};
use crate::account::profile_session::{
    MintDoorError, PersistOutcome, ProfileError, ProfileSession,
};
use crate::account::residency::AccountResidency;
use crate::chain::AbsenceWitness;

/// The launcher id the lineage probe asks about.
///
/// Deliberately a value no singleton can have, so the probe cannot be mistaken for a real read and
/// costs a node nothing to answer. What is under test is whether the call is SERVICED — a source
/// that walks lineages answers `Ok(None)` here, and one that cannot answers `Err`. Reused for the
/// `coin_spend` probe, where `Ok(None)` — unspent or unknown — is likewise the honest answer for a
/// coin that does not exist.
const PROBE_LAUNCHER_ID: Bytes32 = Bytes32::new([0; 32]);

/// The farmer fee a surface-built mint pays, PER BUNDLE, in mojos.
///
/// A whole profile is two bundles, so a user pays twice this plus two singleton mojos — see
/// [`ProfileMint::cost_mojos`], which derives the total from the same [`MintOptions`] the mint is
/// charged under, so a displayed cost can never come to be lower than what is spent.
///
/// # Why a constant and not a preference
///
/// A fee is a bid for inclusion, not a price, and a person has no way to judge one. The value is
/// small enough that being wrong costs a fraction of a cent and large enough to clear an ordinary
/// mempool; it is bounded above by dig-account's own `MAX_MINT_FEE_MOJOS` ceiling, which refuses
/// anything higher, so this cannot become a way to drain a wallet through a config file.
pub const DEFAULT_MINT_FEE_MOJOS: u64 = 10_000;

/// What a WHOLE profile costs at `fee` per bundle, in mojos: two bundles' fees plus the two
/// singleton mojos.
///
/// # Why this is a free function and not only a method
///
/// [`ProfileMint::cost_mojos`] delegates here, and so does every surface that must PRINT the cost
/// before a door exists — the zero-profile funding prompt asks for money on a locked account, where
/// there is no session to build a mint from. Two expressions of one price is how a screen comes to
/// promise a cost lower than the one charged (the shape dig_ecosystem#2377 measured on availability),
/// so there is exactly one, and both callers reach it.
///
/// Saturating throughout: a fee near `u64::MAX` is refused by dig-account's own `MAX_MINT_FEE_MOJOS`
/// ceiling long before it arrives here, and a displayed cost that WRAPPED would show a small number
/// for a large spend.
pub const fn whole_profile_cost_mojos(fee: u64) -> u64 {
    /// The singleton each half of a profile creates, in mojos.
    const SINGLETON_MOJOS_PER_HALF: u64 = 1;
    fee.saturating_add(SINGLETON_MOJOS_PER_HALF)
        .saturating_mul(2)
}

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
    /// The registry could not be READ, so a mint could not be recorded — see
    /// [`MintRefusal::RegistryUnreadable`]. A property of this MACHINE's stored state, not of the
    /// node, and the one arm here whose cost is real XCH spent on a record that would not survive a
    /// restart (dig-app#209).
    RegistryUnreadable,
    /// This account has no free profile index left — see [`MintRefusal::IndexesExhausted`]
    /// (dig-app#263). Terminal, and nothing about the node or the money changes it.
    IndexesExhausted,
    /// The chain is fine and the CEREMONY would refuse: the money is at one index and the new
    /// profile would be created at another (see [`MintRefusal::FundingElsewhere`]).
    ///
    /// A property of the ACCOUNT rather than of the build or the node — the state every account
    /// with at least one profile is already in — which is why it is the one arm carrying a payload:
    /// the remedy names an index, and a sentence that cannot name it is not a remedy.
    FundingElsewhere(FundingElsewhere),
}

/// A mint whose funding index and target index differ, with both named.
///
/// Carries the authority tokens rather than bare indices because this is the SEAM's answer, and the
/// seam is talking to code that may act on it. A copy layer that only prints a number takes a bare
/// `ProfileIx` instead — see `CreationBlocked::FundingElsewhere`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundingElsewhere {
    /// The profile whose wallet holds the money.
    pub funding: WalletSlot,
    /// The profile that would be created.
    pub target: MintTarget,
}

/// Why this ACCOUNT cannot be minted against right now — a fact no amount of waiting on the chain
/// would change.
///
/// Kept apart from [`ProfileMintSeams`], which measures the NODE. A surface that merged the two
/// would tell a person to restart their node about a condition their node has nothing to do with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MintRefusal {
    /// **The registry could not be READ, so a mint could not be RECORDED (dig-app#209).**
    ///
    /// A session whose registry file failed to load falls back to a `MemoryRegistryStore`
    /// (`ProfileSession::unreadable`). Everything else about that session is sound — money and the
    /// recovery phrase stay reachable — but the journal it writes lives only in memory, and a mint
    /// spends real XCH and creates a permanent on-chain identity.
    ///
    /// So a mint attempted here would leave the user having PAID for a DID that this machine
    /// forgets on restart, and `next_free_ix` recomputing from an empty registry would then aim the
    /// NEXT mint at an index that is already occupied. It is the money carve-out on two counts at
    /// once: it lies about money and it lies about whether the act took effect.
    ///
    /// Reported ahead of every other refusal, because it is the one whose cost is unrecoverable.
    RegistryUnreadable,
    /// **This account has no free profile index left (dig-app#263).**
    ///
    /// [`ProfileIx`] is a `u32` and `ProfileRegistry::next_free_ix` is one past the highest index
    /// known, so an account holding `u32::MAX` has nowhere to put another profile. Terminal, and
    /// nothing the person can do resolves it — which is exactly why the surface must SAY so rather
    /// than offer a control that fails.
    ///
    /// Ranked above [`FundingElsewhere`](Self::FundingElsewhere) because with no target index there
    /// is no divergence to describe: the remedy *fund profile N's address* cannot name an N.
    IndexesExhausted,
    /// The money is at one profile's index and the new profile would be created at another, which
    /// dig-account's ceremony cannot express. The remedy names the address to fund.
    FundingElsewhere(FundingElsewhere),
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

    /// Record the confirmed profile in the registry, returning the index it took.
    ///
    /// # Why this takes the EVIDENCE and not a coin id
    ///
    /// [`MintedDid`] and [`ConfirmedStore`] have no public producer. The only place a host can
    /// obtain either is [`ProfileMintStatus::Confirmed`], and that variant is reached only from a
    /// chain read of a coin buried under dig-account's confirmation depth. So a profile cannot be
    /// recorded from a push receipt — **provided no sibling method is ever added that takes a bare
    /// coin id.** One would destroy the property for every caller at once.
    ///
    /// Recording the account's FIRST profile also makes it active, because
    /// [`ProfileRegistry::record_minted`](dig_account::ProfileRegistry::record_minted) sets the
    /// active slot when there is none. There is deliberately no separate switch call here: two
    /// expressions of "which profile is active" is how they come to disagree.
    ///
    /// # Money
    ///
    /// This spends nothing — the spending already happened. It writes the registry, so it can fail
    /// with `mint: None` and a refused persist, which means the profile EXISTS on chain and this
    /// machine will not remember it. That is neither a success nor a failure and must be reported as
    /// itself.
    fn record(
        &self,
        did: &MintedDid,
        store: &ConfirmedStore,
        label: Option<String>,
    ) -> Result<ProfileIx, MintDoorError>;

    /// Why [`begin`](Self::begin) would refuse on this ACCOUNT's own state, or `None` when it would
    /// not refuse.
    ///
    /// # Why a surface ASKS the door instead of deriving the answer itself
    ///
    /// Each of these is one rule with one home, and [`begin`](Self::begin) is gated on the SAME
    /// value a card reads. A card that re-derived any of them would be a second expression of the
    /// same capability, which is the drift dig_ecosystem#2377 measured and dig_ecosystem#2957 is
    /// still open about: the two answers disagree eventually, and the disagreement ships as a
    /// control that offers what the implementation refuses.
    ///
    /// # Why it answers about the account and not the chain
    ///
    /// These are facts a mint could not fix by waiting. The chain's own readiness is measured
    /// separately, by [`ProfileMintSeams::probe`], and collapsing the two would let a transient
    /// outage read as a permanent property of the account.
    ///
    /// Costs nothing, spends nothing, and writes nothing — it reads state already decided.
    fn account_refusal(&self) -> Option<MintRefusal>;
}

/// What the CHAIN answered about minting here — the half of [`ProfileMintSeams`] that needs no door.
///
/// Exists so the slow half of the decision can be taken off the painting thread (see
/// [`ProfileMintSeams::from_readiness`]). It deliberately has **no `availability()`**: an
/// availability read off this type would be a second expression of the same capability, which is the
/// drift dig_ecosystem#2377 measured. To learn whether a profile can be minted, attach a door and ask
/// the seams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainReadiness {
    /// The chain answered the peak AND serviced both source methods the singleton lineage walk composes.
    WalksLineages,
    /// The chain answers ordinary reads and refuses the walk. Carries the source's own words.
    NoLineageWalk {
        /// Why the walk probe failed, verbatim from the chain source.
        why: Arc<str>,
    },
    /// The chain could not be reached at all. Carries the reader's own words.
    NoChainTransport {
        /// Why the chain could not be reached, verbatim from the reader.
        why: Arc<str>,
    },
}

impl ChainReadiness {
    /// Ask `chain` the three questions, in the order that keeps their answers distinguishable.
    ///
    /// Reachability FIRST, and it is a separate question from capability. Once the walk really
    /// works, an offline node fails `resolve_singleton_lineage` too — so a single probe would report
    /// every unplugged machine as *this version cannot finish a mint*, sending somebody to wait for a
    /// release when what they need is to start their node. Asking for the peak first separates
    /// *cannot reach the chain* from *reached it, and it cannot walk a lineage*, which is the entire
    /// reason there are three arms rather than two.
    ///
    /// Every walk `Err` — a timeout, a depth bound, a reveal-size bound — withholds. None of them may
    /// become *absent*: only `Ok` is a capability here, so *I could not read the lineage* can never be
    /// written as *the lineage ends here*, which on a mint path would read as **safe to spend**.
    pub fn probe<C>(chain: &C) -> Self
    where
        C: ChainSource + ?Sized,
    {
        if let Err(why) = chain.peak_height() {
            return Self::NoChainTransport {
                why: why.to_string().into(),
            };
        }

        if let Err(why) = chain.resolve_singleton_lineage(PROBE_LAUNCHER_ID) {
            return Self::NoLineageWalk {
                why: why.to_string().into(),
            };
        }

        // The walk composes exactly TWO source METHODS — `coin_record`, for the launcher and again
        // at every hop (dig-chainsource-interface 0.3.1, `walk.rs:512` and `:592`), and `coin_spend`
        // at every hop (`:547`). Three call sites, two methods. The probe above exercises only the
        // first, because a launcher id naming no coin returns `Ok(None)` out of `read_launcher_coin`
        // (`:389`) before the hop loop begins. So this read is not belt-and-braces: without it
        // `WalksLineages` credits `coin_spend` on no evidence, and a node serving `coin_record` but
        // not `coin_spend` is offered a mint it cannot finish (dig_ecosystem#2685).
        //
        // Asked with the same unreal id for the same reason: what is under test is whether the call
        // is SERVICED, and `Ok(None)` — unspent or unknown — is the honest answer for a coin that
        // does not exist. Only `Err` withholds, so the collapse this whole gate forbids — reading
        // *I could not answer* as *there is nothing there* — stays unwritable here too.
        match chain.coin_spend(PROBE_LAUNCHER_ID) {
            Ok(_) => Self::WalksLineages,
            Err(why) => Self::NoLineageWalk {
                why: why.to_string().into(),
            },
        }
    }
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
    /// This build could not reach the chain at all — the node is not running, or not answering.
    ///
    /// Carries the reader's own words. Distinguished from
    /// [`NoLineageWalk`](Self::NoLineageWalk) by a peak read taken BEFORE the walk probe: once the
    /// walk genuinely works, an unreachable node fails both, and only the order of the two questions
    /// tells them apart.
    NoChainTransport {
        /// Why the chain could not be reached, verbatim from the reader.
        why: Arc<str>,
    },
}

impl<'a> ProfileMintSeams<'a> {
    /// Decide the seams by ASKING the chain whether it can walk a singleton lineage.
    ///
    /// # This is a runtime probe, and its one weakness is stated rather than hidden
    ///
    /// Only `Ok(_)` is accepted from the walk probe; every error withholds the offer. A source that
    /// SERVICES the call and answers *wrongly* would still pass — no probe can see that, which is
    /// precisely why the read delegates to the ecosystem's single hardened walk rather than to
    /// anything written here.
    ///
    /// Every way to be wrong fails in the SAFE direction: any doubt yields a non-`Wired` arm, which
    /// WITHHOLDS the offer. The failure mode this excludes is the expensive one — offering a mint
    /// that strands the user mid-ceremony with real money spent.
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
    /// It proves the SOURCE can service the two source methods a walk composes. It says nothing about any
    /// particular singleton,
    /// and in particular a lineage of exactly `{launcher, eve}` with an unspent eve does **not**
    /// establish that the eve is a genuine singleton curried to that launcher — that rests on the
    /// launcher spender alone. For a DID this host is minting, the launcher spender is this host, so
    /// self-trust covers it. Any future surface resolving a THIRD PARTY's DID from a launcher id
    /// must require a tip beyond the eve, and must not treat this probe as identity verification.
    pub fn probe<C>(mint: &'a dyn ProfileMintDoor, chain: &C) -> Self
    where
        C: ChainSource + ?Sized,
    {
        Self::from_readiness(ChainReadiness::probe(chain), mint)
    }

    /// Attach `mint` to a chain answer taken EARLIER, and possibly on another thread.
    ///
    /// # Why the probe is separable from the door at all
    ///
    /// The three arms are decided entirely by the chain; the door is only carried. A surface that
    /// repaints twice a second therefore cannot afford to probe at paint time — two node round trips
    /// per frame — while the door it must attach borrows a live account session and so cannot leave
    /// the painting thread. Splitting the two lets the slow half run on a worker and the free half
    /// happen in the frame.
    ///
    /// This is the ONE mapping from a chain answer to seams, which is what keeps the split from
    /// becoming the drift the type exists to prevent: [`probe`](Self::probe) routes through it too,
    /// so there is no second expression of "what does a walking chain mean" to disagree with.
    pub fn from_readiness(readiness: ChainReadiness, mint: &'a dyn ProfileMintDoor) -> Self {
        match readiness {
            ChainReadiness::WalksLineages => Self::Wired { mint },
            ChainReadiness::NoLineageWalk { why } => Self::NoLineageWalk { why },
            ChainReadiness::NoChainTransport { why } => Self::NoChainTransport { why },
        }
    }

    /// Whether a whole profile can be minted here — derived from the seams, never asserted beside
    /// them.
    ///
    /// # A wired chain is not by itself a possible mint
    ///
    /// The three seam arms measure the CHAIN. The ceremony has one more refusal that the chain
    /// cannot see: it funds from the index it mints at, so an account whose money sits at a
    /// different index than the one being created is refused at
    /// [`begin`](ProfileMintDoor::begin) however healthy the node is. That is not an edge case —
    /// it is every account holding at least one profile.
    ///
    /// So the wired arm ASKS the door rather than answering for it. Deriving it here rather than
    /// re-comparing two indices is what keeps one rule in one place (dig_ecosystem#2377).
    pub fn availability(&self) -> ProfileMintAvailability {
        match self {
            Self::Wired { mint } => match mint.account_refusal() {
                None => ProfileMintAvailability::Possible,
                Some(MintRefusal::RegistryUnreadable) => {
                    ProfileMintAvailability::RegistryUnreadable
                }
                Some(MintRefusal::IndexesExhausted) => ProfileMintAvailability::IndexesExhausted,
                Some(MintRefusal::FundingElsewhere(divergence)) => {
                    ProfileMintAvailability::FundingElsewhere(divergence)
                }
            },
            Self::NoLineageWalk { .. } => ProfileMintAvailability::NoLineageWalk,
            Self::NoChainTransport { .. } => ProfileMintAvailability::NoChainTransport,
        }
    }

    /// The mint door, or `None` on a build that has none.
    ///
    /// `None` rather than a refusing stand-in: a profile mint has no honest no-op, because "begin"
    /// on a build that cannot finish is the very thing these seams exist to prevent.
    pub fn door(&self) -> Option<&'a dyn ProfileMintDoor> {
        match self {
            Self::Wired { mint } => Some(*mint),
            Self::NoLineageWalk { .. } | Self::NoChainTransport { .. } => None,
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
    C: ChainSource + AbsenceWitness + ?Sized,
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
    ///
    /// # The `ProvablyDead` verdict is warranted, not merely observed (dig-app#208)
    ///
    /// `created`'s absence is what the death verdict below rests on, so the warrant covering it is
    /// sampled IMMEDIATELY after that read — not before (the peak read) and not after (the funding
    /// read) — because [`AbsenceWitness::absence_warrant`] answers from a per-source LATCH
    /// describing whichever read landed most recently
    /// (`crate::chain::source::ControlChainSource::absence_warrant`'s own invariant note). A sample
    /// taken anywhere else would answer about a different read and could report `Warranted` for an
    /// absence the mint coin's own read never warranted.
    ///
    /// `created_coin_id` is a DID or store coin, which dig-node's real source routes to its
    /// fallback tier — the one that always answers `synced: false` — so an unwarranted absence
    /// there is the ordinary case, not a rare one: a mint that genuinely confirmed (its funding coin
    /// legitimately spent by the mint itself, its own coin present on chain but not yet visible to
    /// the tier that answered) produces exactly `created.is_none() && funding.spent_height.is_some()`.
    /// Told that is proof of death, a person re-mints, pays a second time, and owns a stranded
    /// orphan profile.
    fn read<C>(&self, chain: &C) -> MintLiveness
    where
        C: ChainSource + AbsenceWitness + ?Sized,
    {
        let Ok(Some(peak)) = chain.peak_height() else {
            return MintLiveness::Unknown;
        };
        let Ok(created) = chain.coin_record(self.created_coin_id) else {
            return MintLiveness::Unknown;
        };
        let created_absence_warrant = chain.absence_warrant();
        let Ok(funding) = chain.coin_record(self.funding_coin_id) else {
            return MintLiveness::Unknown;
        };

        // The coin this bundle creates EXISTS, so the bundle was included. Nothing to declare.
        // Self-warranting: a coin that is PRESENT needs no warrant, only an absence does.
        if created.is_some() {
            return MintLiveness::Waiting {
                blocks_since_push: peak.saturating_sub(self.pushed_at_height),
            };
        }

        // The funding coin is gone and the coin it should have created never appeared: some other
        // spend consumed it, and this bundle can never be included -- PROVIDED the created coin's
        // own absence can be believed. An unwarranted absence degrades to Unknown rather than
        // ProvablyDead: an unknown mint is waited on, a wrongly-failed one is mourned.
        if let Some(spent_at) = funding.and_then(|record| record.spent_height) {
            if !created_absence_warrant.believable() {
                return MintLiveness::Unknown;
            }
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
    /// The index the new profile derives at, or `None` when the account has none free.
    ///
    /// An `Option` rather than a value chosen at construction, because the alternative is to invent
    /// an index for an exhausted account and every index that could be invented is one that may
    /// already hold a profile (see [`MintTarget::next_free`]). Carrying the absence this far means
    /// every door operation has to confront it, which is where the refusal belongs — a surface-only
    /// check would be satisfied by any caller that skipped the surface.
    target: Option<MintTarget>,
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
        target: Option<MintTarget>,
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

    /// The door a SURFACE builds: mainnet, at [`DEFAULT_MINT_FEE_MOJOS`], funding from the profile
    /// whose wallet is live and creating the next free one.
    ///
    /// # Why the surface does not get to choose these
    ///
    /// `new` takes eight arguments because a mint has eight distinct authorities, and four of them
    /// are DECISIONS — which wallet pays, which index is created, which network's signature domain
    /// is used, and what is paid to the farmer. A binary is a test-free zone, so a binary that
    /// answered them would be answering money questions no test can execute. Here they are answered
    /// once, from the session, under test.
    ///
    /// The two slots are read from the SAME [`ProfileSession`] the door writes to, so a mint can
    /// never be journalled against a registry other than the one its indices were read from.
    ///
    /// # Money
    ///
    /// Constructing this spends nothing; [`ProfileMintDoor::begin`] does. On mainnet the total is
    /// [`cost_mojos`](Self::cost_mojos) — two bundles at [`DEFAULT_MINT_FEE_MOJOS`] plus two
    /// singleton mojos.
    pub fn for_session(
        session: &'a ProfileSession,
        residency: &'a AccountResidency,
        chain: &'a C,
        publisher: &'a P,
    ) -> Self {
        Self::new(
            session,
            residency,
            session.wallet_slot(),
            session.next_mint_target(),
            chain,
            publisher,
            MintNetwork::mainnet(),
            MintOptions::with_fee(DEFAULT_MINT_FEE_MOJOS),
        )
    }

    /// The total a whole profile costs, in mojos: two bundles' fees plus the two singleton mojos.
    ///
    /// Derived from the SAME [`MintOptions`] the mint is charged under, so a displayed cost cannot
    /// come to be lower than what is spent.
    pub fn cost_mojos(&self) -> u64 {
        whole_profile_cost_mojos(self.options.fee)
    }

    /// dig-account's minter, derived fresh.
    ///
    /// **Derived before any registry lock is taken**, deliberately: this touches the account mutex,
    /// and [`ProfileSession`]'s lock-ordering rule forbids taking that mutex while a registry guard
    /// is held.
    fn minter(&self) -> Result<dig_account::ProfileMinter, MintError> {
        self.residency.profile_minter().ok_or(MintError::Locked)
    }

    /// The target index, or the refusal that stands in its way — **the ONE gate every door
    /// operation passes through**.
    ///
    /// # Why the gate returns the target rather than sitting beside it
    ///
    /// Because a guard a caller can forget is a guard that will be forgotten. `begin`, `advance`,
    /// `status`, `liveness` and `record` all need the index, so making the index obtainable ONLY
    /// through the refusal check means no operation can proceed without having answered it. That is
    /// a placement decision: the same three refusals checked at the surface would be satisfied by
    /// any path that did not go through the surface.
    ///
    /// The refusals are ordered by [`MintRefusal`]'s own ranking, which each arm justifies.
    fn checked_target(&self) -> Result<MintTarget, MintError> {
        match self.refusal() {
            None => self.target.ok_or_else(|| {
                // Unreachable while `account_refusal` reports `IndexesExhausted` for exactly the
                // `None` target, and expressed as an error rather than an `expect` so that a future
                // divergence between the two costs a refusal instead of a panic on a money path.
                MintError::Refused(copy_indexes_exhausted())
            }),
            Some(MintRefusal::RegistryUnreadable) => {
                Err(MintError::Refused(copy_registry_unreadable()))
            }
            Some(MintRefusal::IndexesExhausted) => {
                Err(MintError::Refused(copy_indexes_exhausted()))
            }
            Some(MintRefusal::FundingElsewhere(FundingElsewhere { funding, target })) => Err(
                MintError::Refused(divergent_indices_message(funding.ix(), target.ix())),
            ),
        }
    }

    /// Why this account refuses a mint, or `None` when it does not — the single home of the rule
    /// [`ProfileMintDoor::account_refusal`] exposes and [`checked_target`](Self::checked_target)
    /// enforces.
    ///
    /// # dig-account's ceremony cannot express a divergent mint, which is why that arm exists
    ///
    /// It mints at an index AND funds from that same index's wallet: passing the target would spend
    /// from a brand-new profile's empty wallet, and passing the funding index would mint at the
    /// wrong one. The citation here was once dig_ecosystem#2496, as though a dig-account release
    /// would remove the need for it — that release happened (0.13 exposes `wallet_ops_at(ix)`) and
    /// the ceremony still funds from the index it mints at, so the refusal stands unchanged. It is
    /// the state EVERY second profile begins in, not a defensive one.
    fn refusal(&self) -> Option<MintRefusal> {
        if self.session.unreadable_reason().is_some() {
            return Some(MintRefusal::RegistryUnreadable);
        }
        let Some(target) = self.target else {
            return Some(MintRefusal::IndexesExhausted);
        };
        match self.funding.ix() == target.ix() {
            true => None,
            false => Some(MintRefusal::FundingElsewhere(FundingElsewhere {
                funding: self.funding,
                target,
            })),
        }
    }
}

/// What a person is told when the money is at one index and the profile would be created at
/// another. The message IS the remedy — a refusal that cannot name the address to fund tells
/// somebody they are blocked without telling them where to go.
fn divergent_indices_message(funding: ProfileIx, target: ProfileIx) -> String {
    format!(
        "This mint would pay from profile {funding} but create profile {target}, and DIG cannot \
         yet fund one profile's mint from another's wallet. Move funds to profile {target}'s \
         address first."
    )
}

/// The error for a `record` this session refused: the profile is CONFIRMED on chain and was NOT
/// written to disk.
///
/// # Why the `persisted` field must be `NotWritten` here
///
/// [`MintDoorError::may_be_forgotten`] reads that field alone, and it is the one question a surface
/// must ask before telling somebody to try again. Reaching `record` at all means the caller holds
/// `MintedDid` + `ConfirmedStore`, which exist only for a mint confirmed on chain — so money has
/// certainly moved, and refusing to write it means exactly "this host paid for a profile it will not
/// remember". `PersistOutcome::Written` would INVERT that: the warning surface would be told the
/// record is safe on disk when nothing was written, and a person could be walked into paying twice
/// for an identity they already own.
///
/// # Why it is a named function rather than a literal at the call site
///
/// Because the call site cannot be reached from a test. [`ProfileMintDoor::record`] consumes
/// `MintedDid` and `ConfirmedStore`, which have no public constructor outside dig-account — the same
/// property that makes a DID unrecordable without on-chain proof. Naming this gives the rule
/// somewhere to be checked; the binding to production is a direct call, in `record`'s single `Err`
/// arm. The arm is also unreachable in production today, since a door that refuses here refuses
/// `begin` and `advance` at the same gate, which is precisely why an inversion could sit unnoticed.
fn unrecorded(mint: MintError) -> MintDoorError {
    MintDoorError {
        mint: Some(mint),
        persisted: PersistOutcome::NotWritten(ProfileError::Corrupt(
            "the session cannot record a mint, so the confirmed profile reached no disk"
                .to_string(),
        )),
    }
}

/// What a person is told when the registry could not be read. It names the cost of proceeding —
/// paying for something this machine would forget — because that is the fact that makes waiting the
/// cheaper choice.
fn copy_registry_unreadable() -> String {
    "DIG could not read this account's profile list, so a new profile could not be recorded here. \
     Creating one now would spend XCH on an identity this machine would forget when it restarts. \
     Restart DIG to try reading the list again."
        .to_owned()
}

/// What a person is told when the account has no index left. There is no remedy to offer, so the
/// sentence offers none — inventing one would be the unbacked promise `professional-ui` forbids.
fn copy_indexes_exhausted() -> String {
    "This account has no room for another profile — every profile index it can use is taken. \
     Existing profiles are unaffected."
        .to_owned()
}

impl<C, P> ProfileMintDoor for ProfileMint<'_, C, P>
where
    C: ChainSource + AbsenceWitness + Sized,
    P: SpendPublisher + ?Sized,
{
    fn begin(&self, seed: &ProfileSeed) -> Result<ProfileMintStatus, MintDoorError> {
        let prepared = self.checked_target().and_then(|t| Ok((t, self.minter()?)));
        let (target, minter) = match prepared {
            Ok(ready) => ready,
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
                target.ix(),
                seed,
                self.chain,
                self.publisher,
                &self.network,
                &self.options,
                &crate::wallet::reservations::shared(),
            )
        })
    }

    fn account_refusal(&self) -> Option<MintRefusal> {
        self.refusal()
    }

    fn advance(&self) -> Result<ProfileMintStatus, MintDoorError> {
        let prepared = self.checked_target().and_then(|t| Ok((t, self.minter()?)));
        let (target, minter) = match prepared {
            Ok(ready) => ready,
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
                target.ix(),
                self.chain,
                self.publisher,
                &self.network,
                &crate::wallet::reservations::shared(),
            )
        })
    }

    fn status(&self) -> Result<ProfileMintStatus, MintError> {
        // `&self` over a `&`-registry: there is no argument that makes this move money, which is
        // what lets a "Check again" control exist in the waiting state at all.
        let target = self.checked_target()?;
        let minter = self.minter()?;
        self.session
            .with_registry(|registry| minter.profile_mint_status(registry, target.ix(), self.chain))
    }

    fn liveness(&self) -> Option<MintLiveness> {
        liveness_of(self.session, self.checked_target().ok()?.ix(), self.chain)
    }

    fn record(
        &self,
        did: &MintedDid,
        store: &ConfirmedStore,
        label: Option<String>,
    ) -> Result<ProfileIx, MintDoorError> {
        let ix = match self.checked_target() {
            Ok(target) => target.ix(),
            Err(mint) => return Err(unrecorded(mint)),
        };
        // No minter is derived, so the lock-ordering rule `begin` and `advance` obey — take the
        // account mutex BEFORE the registry write lock — has nothing to bind here.
        self.session.with_journal(|registry| {
            registry
                .record_minted(ix, did, store, label)
                .map(|_| ix)
                .map_err(|why| MintError::Journal(why.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::profile_session::test_support::{registry_with, session_with};
    use crate::chain::AbsenceWarrant;
    use crate::profiles::{CreationBlocked, ProfileCreation};
    use dig_account::registry::journal::{
        MintedDidRecord, PendingMintRecord, PendingStoreLaunchRecord,
    };
    use dig_account::registry::ProfileRegistry;
    use dig_account::ProfileIx;
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

    /// A chain source with the two probe answers on INDEPENDENT knobs.
    ///
    /// # Why the shared `MockChainSource` cannot be used here
    ///
    /// Its `fail_with` fails EVERY read, peak included, so `with_peak(..).fail_with(..)` still yields
    /// a source whose peak errors. That double can express *everything works* and *nothing works*,
    /// and the state this gate exists to distinguish — **the peak answers and the walk does not** —
    /// is not among them. A test written against it can only ever confirm the two states the probe
    /// already got right, which is how a fixture comes to prove a property it cannot see.
    struct TwoKnobChain {
        /// What `peak_height` answers. `None` = the read fails, i.e. nothing is reachable.
        peak: Option<u32>,
        /// Whether the singleton lineage walk is serviced.
        walks: bool,
        /// Whether `coin_spend` — the second of the two source methods the walk composes — is serviced.
        ///
        /// A third knob because a two-knob double cannot express the state dig_ecosystem#2685
        /// measured: the walk probe answers, and the read the walk needs at its first hop does not.
        /// A double that could only vary `walks` cannot express that multi-field lie, so it would
        /// confirm the probe against exactly the states the probe already got right.
        serves_coin_spend: bool,
    }

    impl TwoKnobChain {
        /// A node that answers everything the probe asks — the control.
        fn wired() -> Self {
            Self {
                peak: Some(PEAK),
                walks: true,
                serves_coin_spend: true,
            }
        }
    }

    impl ChainSource for TwoKnobChain {
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
            match self.serves_coin_spend {
                true => Ok(None),
                false => Err("this node does not serve coin_spend".to_owned()),
            }
        }
        fn resolve_singleton_lineage(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<SingletonLineage>, Self::Error> {
            // Deliberately does NOT consult `serves_coin_spend`, because the real
            // `walk_singleton_lineage` does not either for a launcher id that names no coin: it
            // returns `Ok(None)` from `read_launcher_coin` before the hop loop — and therefore
            // before `coin_spend` — ever runs (dig-chainsource-interface 0.3.1, `walk.rs:389`).
            // A double that routed the walk through `coin_spend` would make
            // `a_node_that_cannot_serve_the_hop_read_is_not_credited_with_walking_lineages` pass
            // against the very code it exists to fail, which is a fixture proving a property it
            // cannot see.
            match self.walks {
                true => Ok(None),
                false => Err("this node does not serve a lineage walk".to_owned()),
            }
        }
        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            self.peak
                .map(Some)
                .ok_or_else(|| "connection refused".to_owned())
        }
        fn block_timestamp(&self, _h: u32) -> Result<Option<u64>, Self::Error> {
            Ok(None)
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

    /// Every one of `WalksLineages`'s answers is authoritative by construction (a hand-built fixture,
    /// not a replica behind a real node), so its absences are the chain's own.
    impl AbsenceWitness for WalksLineages {
        fn absence_warrant(&self) -> AbsenceWarrant {
            AbsenceWarrant::Warranted
        }
    }

    /// A mint door that records whether anything asked it to spend.
    ///
    /// `divergence` is a knob rather than a constant so the seam's fourth arm can be exercised
    /// without standing up a real account: the two authority tokens have no bare constructor, and
    /// the ONE the tests can build honestly is `WalletSlot::unprofiled()` beside a `MintTarget`
    /// taken from a registry that already holds a profile.
    #[derive(Default)]
    struct CountingDoor {
        begins: std::cell::Cell<usize>,
        divergence: Option<FundingElsewhere>,
    }

    impl CountingDoor {
        /// A door whose money is at ROOT and whose target is the next free index of `registry`.
        fn paying_from_elsewhere(registry: &ProfileRegistry) -> Self {
            Self {
                begins: std::cell::Cell::default(),
                divergence: Some(FundingElsewhere {
                    funding: WalletSlot::unprofiled(),
                    target: MintTarget::next_free(registry)
                        .expect("a fixture registry is never index-exhausted"),
                }),
            }
        }
    }

    impl ProfileMintDoor for CountingDoor {
        fn account_refusal(&self) -> Option<MintRefusal> {
            self.divergence.map(MintRefusal::FundingElsewhere)
        }

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
        fn record(
            &self,
            _did: &MintedDid,
            _store: &ConfirmedStore,
            _label: Option<String>,
        ) -> Result<ProfileIx, MintDoorError> {
            // Unreachable from these tests by construction: reaching it needs mint evidence, which
            // has no public producer. The double cannot fabricate one, and that is the point.
            unreachable!("the seam tests never confirm a mint")
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
        // Reachable — the peak answers — and unable to walk. The distinction the shared mock cannot
        // express, which is why this uses the two-knob double.
        let refuses = TwoKnobChain {
            peak: Some(PEAK),
            walks: false,
            serves_coin_spend: true,
        };

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

    /// **A node that answers the walk probe but cannot serve the read the walk needs at its first
    /// hop is NOT credited with walking lineages** (dig_ecosystem#2685).
    ///
    /// Makes impossible: the fail-OPEN money gate. `PROBE_LAUNCHER_ID` names no coin, so the
    /// canonical `walk_singleton_lineage` returns `Ok(None)` out of `read_launcher_coin` **before
    /// the hop loop runs** — meaning the probe's one `Ok(_)` measures `coin_record` alone and
    /// credits `coin_spend` on no evidence at all. A dig-node that serves `peak` and `coin_record`
    /// and answers `METHOD_NOT_FOUND` for `coin_spend` therefore probes as `WalksLineages` →
    /// `Wired` → `Possible`, and the app offers a create control against a node that cannot finish
    /// phase B: real XCH spent, stranded at `DidConfirmedStoreNotLaunched`.
    ///
    /// # Why this fixture can see it and the existing ones cannot
    ///
    /// The two knobs both existing probe tests vary are `peak` and `walks`, and this defect lives in
    /// neither: it needs `walks: true` — an honestly-answering walk probe — beside a broken
    /// `coin_spend`. That is a two-field lie, and a double that could only vary one field could not
    /// state it. The double's walk deliberately does not consult `coin_spend`, exactly as the real
    /// walk does not, so this cannot pass against the pre-fix body.
    ///
    /// The control varies ONE field back and requires a real `Possible` from the same function, so an
    /// implementation that refused everything cannot pass either.
    #[test]
    fn a_node_that_cannot_serve_the_hop_read_is_not_credited_with_walking_lineages() {
        let door = CountingDoor::default();
        let no_hop_read = TwoKnobChain {
            serves_coin_spend: false,
            ..TwoKnobChain::wired()
        };

        assert_eq!(
            ProfileMintSeams::probe(&door, &no_hop_read).availability(),
            ProfileMintAvailability::NoLineageWalk,
            "a node missing one of the two source methods the walk composes cannot finish phase B, and \
             crediting it spends a user's XCH on a profile that can never complete"
        );
        assert_eq!(
            door.begins.get(),
            0,
            "a withheld offer must not have reached the mint at all"
        );

        // Control: the SAME door and the SAME walk answer, with only the hop read restored.
        assert_eq!(
            ProfileMintSeams::probe(&door, &TwoKnobChain::wired()).availability(),
            ProfileMintAvailability::Possible,
            "the control must genuinely be offered, or the refusal above proves nothing"
        );
    }

    /// **An unreachable node reads as `NoChainTransport`, NOT as `NoLineageWalk`.**
    ///
    /// Makes impossible: telling somebody whose dig-node is simply not running that *this version of
    /// DIG cannot finish creating a profile*. That sends them to wait for a release when what they
    /// need is to start their node, and it is the exact regression that arrives the moment the walk
    /// starts working — before that, an offline node and a walk-less node were indistinguishable
    /// because BOTH failed the walk probe, so a single-probe gate was defensible. It is not any more.
    ///
    /// The three legs vary ONE thing each, against the same door:
    ///   * nothing answers            -> `NoChainTransport`
    ///   * the peak answers, the walk does not -> `NoLineageWalk`
    ///   * both answer                -> `Possible`
    ///
    /// The middle leg is the load-bearing one. Without it, a probe that returned `NoChainTransport`
    /// for every failure would pass the other two, and the whole three-arm distinction would be
    /// decoration.
    #[test]
    fn an_unreachable_node_is_not_reported_as_a_build_that_cannot_finish_a_mint() {
        let door = CountingDoor::default();

        // Nothing answers at all: neither the peak nor the walk.
        let offline = TwoKnobChain {
            peak: None,
            walks: false,
            serves_coin_spend: true,
        };
        assert_eq!(
            ProfileMintSeams::probe(&door, &offline).availability(),
            ProfileMintAvailability::NoChainTransport,
            "a node that is not running must be reported as unreachable, not as an old build"
        );

        // The peak answers; only the walk is missing. This is a node too old to serve it.
        let no_walk = TwoKnobChain {
            peak: Some(PEAK),
            walks: false,
            serves_coin_spend: true,
        };
        assert_eq!(
            ProfileMintSeams::probe(&door, &no_walk).availability(),
            ProfileMintAvailability::NoLineageWalk,
            "a reachable node that cannot walk a lineage is a DIFFERENT fault with a different remedy"
        );

        // Both answer.
        assert_eq!(
            ProfileMintSeams::probe(&door, &WalksLineages).availability(),
            ProfileMintAvailability::Possible
        );

        assert_eq!(
            door.begins.get(),
            0,
            "probing must never ask the mint to spend"
        );
    }

    /// **A healthy node whose money sits at another index reads as `FundingElsewhere`, NOT as
    /// `Possible`** (dig_ecosystem#2939).
    ///
    /// Makes impossible: the card offering profile creation to every account that already holds
    /// one. `begin` refuses whenever funding and target differ, and that is the state EVERY
    /// second-and-later profile starts in — so a seam answering only about the chain calls the
    /// refusing case possible, and the person is walked into a ceremony that cannot start.
    ///
    /// # Why the fixture varies the DOOR and not the chain
    ///
    /// The defect is invisible to every chain knob: this node is perfectly healthy, and the three
    /// existing probe tests would pass unchanged against it. What differs is the account — one
    /// profile already exists, so the next free index is not the wallet's. The control leg is the
    /// same wired chain with a door funding at its own target, which must still be `Possible`, so
    /// an implementation that refused every wired seam cannot pass either.
    #[test]
    fn a_mint_funded_from_another_profile_is_not_reported_as_possible() {
        let registry = registry_with(&[(ProfileIx::ROOT, Some("home"))]);
        let elsewhere = CountingDoor::paying_from_elsewhere(&registry);

        let seams = ProfileMintSeams::probe(&elsewhere, &WalksLineages);

        assert_eq!(
            seams.availability(),
            ProfileMintAvailability::FundingElsewhere(FundingElsewhere {
                funding: WalletSlot::unprofiled(),
                target: MintTarget::next_free(&registry)
                    .expect("a fixture registry is never index-exhausted"),
            }),
            "an account whose money is at one index and whose next profile is at another was told \
             a mint is possible, and `begin` refuses it"
        );
        assert_eq!(
            elsewhere.begins.get(),
            0,
            "deciding availability must never ask the mint to spend"
        );

        // Control: the SAME wired chain, a door with nothing diverging.
        assert_eq!(
            ProfileMintSeams::probe(&CountingDoor::default(), &WalksLineages).availability(),
            ProfileMintAvailability::Possible,
            "the control must genuinely be offered, or the refusal above proves nothing"
        );
    }

    /// **The availability and the obtainable door cannot disagree, in EITHER direction.**
    ///
    /// Makes impossible: the dig_ecosystem#2377 defect, where the gate lived in one expression and
    /// the capability in another, so a one-line edit to the gate opened a dead end. Asserted over
    /// all four arms so neither "always `Some`" nor "always `None`" survives.
    ///
    /// # The rule is about the CHAIN, and `FundingElsewhere` is why that had to be said out loud
    ///
    /// A door is offered exactly when the chain can carry the ceremony. `FundingElsewhere` is a
    /// refusal `begin` makes, not an absent seam: an account with a mint ALREADY IN FLIGHT must
    /// still be able to `advance` and `status` it, and taking the door away would strand exactly
    /// the person who has already spent money. So that arm keeps its door and withholds only the
    /// OFFER — which is the surface's job, and is `is_possible()`, never `door().is_some()`.
    #[test]
    fn availability_and_the_door_agree_on_every_arm() {
        let door = CountingDoor::default();
        let registry = registry_with(&[(ProfileIx::ROOT, Some("home"))]);
        let elsewhere = CountingDoor::paying_from_elsewhere(&registry);
        let refusing = TwoKnobChain {
            peak: Some(PEAK),
            walks: false,
            serves_coin_spend: true,
        };

        for seams in [
            ProfileMintSeams::probe(&door, &WalksLineages),
            ProfileMintSeams::probe(&elsewhere, &WalksLineages),
            ProfileMintSeams::probe(&door, &refusing),
            ProfileMintSeams::NoChainTransport {
                why: "the node is not running".into(),
            },
        ] {
            let chain_carries_it = !matches!(
                seams.availability(),
                ProfileMintAvailability::NoLineageWalk | ProfileMintAvailability::NoChainTransport
            );
            assert_eq!(
                chain_carries_it,
                seams.door().is_some(),
                "a {:?} build must offer a door exactly when the chain can carry the ceremony",
                seams.availability()
            );
        }

        // The other half, which the loop above deliberately does NOT cover: a door that survives
        // its arm must not be mistaken for an offer.
        assert!(
            !matches!(
                ProfileMintSeams::probe(&elsewhere, &WalksLineages).availability(),
                ProfileMintAvailability::Possible
            ),
            "a divergent mint kept its door AND was reported possible, which is the offer the \
             ceremony refuses"
        );
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
    fn succeeded_reading<C: ChainSource + AbsenceWitness + ?Sized>(
        flight: &InFlight,
        chain: &C,
    ) -> MintLiveness {
        flight.read(chain)
    }

    /// A chain that latches its absence warrant PER READ, exactly as [`ControlChainSource`] does.
    ///
    /// # Why a double with one constant warrant is not enough
    ///
    /// [`ControlChainSource::absence_warrant`] answers from a per-SOURCE latch that every read
    /// overwrites (`note_freshness`), so WHICH read the warrant describes depends entirely on which
    /// read happened last. A double answering one constant warrant returns the same value wherever
    /// the sample is taken, so it cannot tell a warrant taken on the mint coin's read apart from one
    /// taken on the funding read that follows it — and the placement is the whole fix. This double
    /// makes the latch observable by giving every read its own warrant.
    ///
    /// A coin the fixture never listed PANICS rather than defaulting. A default would silently
    /// decide the very thing each test is varying.
    struct LatchingChain {
        /// The peak, and the warrant its read latches. Read FIRST, so a sample taken too EARLY —
        /// before the mint coin is read at all — sees this one.
        peak: (u32, AbsenceWarrant),
        /// Every coin the fixture speaks about: its id, the record (or its absence), and the warrant
        /// that coin's read latches.
        coins: Vec<(Bytes32, Option<CoinRecord>, AbsenceWarrant)>,
        /// The warrant the most recent read left behind — the latch itself.
        latched: std::cell::RefCell<AbsenceWarrant>,
    }

    impl LatchingChain {
        fn new(peak: (u32, AbsenceWarrant)) -> Self {
            Self {
                peak,
                coins: Vec::new(),
                // Nothing has been read, so nothing is warranted — the same starting state
                // `ControlChainSource` has before its first answer.
                latched: std::cell::RefCell::new(withheld("no read has landed yet")),
            }
        }

        /// Adds a coin the chain HOLDS, whose read latches `warrant`.
        fn holding(mut self, id: Bytes32, record: CoinRecord, warrant: AbsenceWarrant) -> Self {
            self.coins.push((id, Some(record), warrant));
            self
        }

        /// Adds a coin the chain reports ABSENT, whose read latches `warrant`.
        fn missing(mut self, id: Bytes32, warrant: AbsenceWarrant) -> Self {
            self.coins.push((id, None, warrant));
            self
        }
    }

    impl ChainSource for LatchingChain {
        type Error = String;
        fn coin_record(&self, id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            let (_, record, warrant) = self
                .coins
                .iter()
                .find(|(known, _, _)| *known == id)
                .expect("the fixture must state a record AND a warrant for every coin read");
            *self.latched.borrow_mut() = warrant.clone();
            Ok(record.clone())
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
            Ok(None)
        }
        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            *self.latched.borrow_mut() = self.peak.1.clone();
            Ok(Some(self.peak.0))
        }
        fn block_timestamp(&self, _h: u32) -> Result<Option<u64>, Self::Error> {
            Ok(None)
        }
    }

    impl AbsenceWitness for LatchingChain {
        fn absence_warrant(&self) -> AbsenceWarrant {
            self.latched.borrow().clone()
        }
    }

    /// A withheld warrant, phrased the way a real source phrases one.
    fn withheld(because: &str) -> AbsenceWarrant {
        AbsenceWarrant::Withheld {
            because: because.to_owned(),
        }
    }

    /// The evidence the fixtures below expect when death really is proven.
    fn proven_death() -> MintLiveness {
        MintLiveness::ProvablyDead {
            evidence: DeathEvidence {
                funding_coin_id: coin_id(2),
                funding_spent_at: PUSHED_AT + 3,
                absent_did_coin_id: coin_id(3),
            },
        }
    }

    /// **A mint coin that reads as absent from a source which cannot warrant an absence is
    /// `Unknown` — never `ProvablyDead`.**
    ///
    /// Makes impossible: dig_ecosystem#208. `coin_record` maps to `control.wallet.coinById`, which
    /// dig-node routes to its fallback tier and answers `synced: false` on EVERY reply
    /// (`chain/source.rs:294-320`). A mint that genuinely CONFIRMED — its funding coin legitimately
    /// spent by the mint itself, its own coin present on chain but not yet visible to the tier that
    /// answered — produces exactly `created.is_none() && funding.spent_height.is_some()`. Told that
    /// is provable death, a person re-mints, pays a second time, and owns a stranded orphan DID.
    ///
    /// The second leg is what stops "always answer `Unknown`" from passing: the SAME reads with the
    /// warrant granted must still reach the death verdict, so the arm is guarded rather than
    /// removed.
    #[test]
    fn an_absence_the_source_cannot_warrant_is_unknown_rather_than_provably_dead() {
        let flight = InFlight {
            funding_coin_id: coin_id(2),
            created_coin_id: coin_id(3),
            pushed_at_height: PUSHED_AT,
        };
        let unwarranted = withheld(
            "the tier that answered reported synced=false (source: fallback), so it cannot tell an \
             absence apart from a view that is merely behind",
        );

        // The shape of a confirmed mint seen through a tier that is behind: the funding coin spent
        // (by this very mint), the coin it created not yet visible, and the source saying so.
        let behind = LatchingChain::new((PEAK, unwarranted.clone()))
            .missing(coin_id(3), unwarranted.clone())
            .holding(
                coin_id(2),
                spent_at(coin_id(2), PUSHED_AT + 3),
                unwarranted.clone(),
            );
        assert_eq!(
            flight.read(&behind),
            MintLiveness::Unknown,
            "a mint was called provably dead on an absence its own source refused to warrant"
        );

        // Control: the identical reads from a source that DOES warrant its absences. Death is still
        // reachable, so the guard narrows the arm rather than deleting it.
        let synced = LatchingChain::new((PEAK, AbsenceWarrant::Warranted))
            .missing(coin_id(3), AbsenceWarrant::Warranted)
            .holding(
                coin_id(2),
                spent_at(coin_id(2), PUSHED_AT + 3),
                AbsenceWarrant::Warranted,
            );
        assert_eq!(
            flight.read(&synced),
            proven_death(),
            "a warranted absence beside a spent funding coin is still proof of death"
        );
    }

    /// **The warrant is taken on the MINT COIN's read — not on the peak before it, and not on the
    /// funding read after it.**
    ///
    /// Makes impossible: the silent break `chain/source.rs:183-207` names in its own words. The
    /// warrant is a per-source LATCH that every read overwrites, so a sample taken anywhere but
    /// beside the read it describes answers about a different read. `InFlight::read` makes THREE
    /// reads where the latch's one prior caller made two, and the LAST of the three is the funding
    /// coin — wallet-scoped, and the one read that can legitimately report `synced: true`. A sample
    /// taken after it would answer `Warranted` for an absence nothing warranted, leaving the guard
    /// apparently in place and doing nothing.
    ///
    /// # Why both legs are needed, and why they are exact inverses
    ///
    /// Each leg gives the mint-coin read one warrant and BOTH surrounding reads the opposite one, so
    /// a sample taken too early or too late lands on the inverse verdict in both. A single leg — or
    /// a double answering one constant warrant — is satisfied by every placement, which is how a
    /// placement fix comes to be pinned by a test that cannot see it.
    #[test]
    fn the_warrant_is_taken_on_the_mint_coin_read_not_on_whichever_read_landed_last() {
        let flight = InFlight {
            funding_coin_id: coin_id(2),
            created_coin_id: coin_id(3),
            pushed_at_height: PUSHED_AT,
        };

        // The mint coin's read withholds; the peak before it and the funding read after it both
        // warrant. Only a warrant taken on the mint coin's own read sees the refusal.
        let withholding_mint_read = LatchingChain::new((PEAK, AbsenceWarrant::Warranted))
            .missing(
                coin_id(3),
                withheld("the fallback tier answered for the mint coin"),
            )
            .holding(
                coin_id(2),
                spent_at(coin_id(2), PUSHED_AT + 3),
                AbsenceWarrant::Warranted,
            );
        assert_eq!(
            flight.read(&withholding_mint_read),
            MintLiveness::Unknown,
            "the warrant was read off a neighbouring read, so the guard passed an absence nothing \
             warranted"
        );

        // The exact inverse: the mint coin's read warrants and both neighbours withhold. Death is
        // proven, and a sample taken from either neighbour would wrongly degrade it to Unknown.
        let warranting_mint_read = LatchingChain::new((PEAK, withheld("the peak read was behind")))
            .missing(coin_id(3), AbsenceWarrant::Warranted)
            .holding(
                coin_id(2),
                spent_at(coin_id(2), PUSHED_AT + 3),
                withheld("the funding read was behind"),
            );
        assert_eq!(
            flight.read(&warranting_mint_read),
            proven_death(),
            "the mint coin's own read warranted its absence, so the death verdict stands"
        );
    }

    /// A chain whose peak answers and whose `coin_record` fails for ONE named coin.
    ///
    /// # Why the shared `MockChainSource` cannot express this
    ///
    /// Its `fail_with` arms one error across every method, peak included, so the state that
    /// distinguishes a real implementation from `chain.coin_record(..).unwrap_or(None)` — *the peak
    /// is known, and one coin read failed* — is not among the states it can produce. A suite written
    /// only against it stays green under that mutation while a user is told a live mint is dead.
    struct OneCoinFails {
        /// The coin whose read fails. Every other coin answers from `records`.
        failing: Bytes32,
        /// The coins this chain knows about.
        records: Vec<(Bytes32, CoinRecord)>,
    }

    impl ChainSource for OneCoinFails {
        type Error = String;
        fn coin_record(&self, id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            if id == self.failing {
                return Err("the read timed out".to_owned());
            }
            Ok(self
                .records
                .iter()
                .find(|(known, _)| *known == id)
                .map(|(_, record)| record.clone()))
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
            Ok(None)
        }
        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            Ok(Some(PEAK))
        }
        fn block_timestamp(&self, _h: u32) -> Result<Option<u64>, Self::Error> {
            Ok(None)
        }
    }

    /// The value this returns is never load-bearing for the failed-read tests below — a failed
    /// `coin_record` always reaches `Unknown` regardless of what the warrant says — but the bound
    /// `read` now carries requires an answer to compile at all.
    impl AbsenceWitness for OneCoinFails {
        fn absence_warrant(&self) -> AbsenceWarrant {
            AbsenceWarrant::Warranted
        }
    }

    /// **A FAILED coin read is `Unknown`, on EITHER coin independently — never an absent coin.**
    ///
    /// Makes impossible: `chain.coin_record(..).unwrap_or(None)`, in either position. Both legs are
    /// needed because the two reads fail into different lies, and a suite covering one leg cannot see
    /// the other:
    ///
    /// - the CREATED coin swallowed reads as *the mint's coin does not exist*, which combined with a
    ///   spent funding coin is exactly the shape of [`MintLiveness::ProvablyDead`] — a live, paid-for
    ///   mint reported dead, which invites a second spend;
    /// - the FUNDING coin swallowed reads as *the funding coin is unspent*, which reports `Waiting`
    ///   for a mint the chain could genuinely prove dead.
    ///
    /// Each leg's fixture is arranged so the mutation produces a DIFFERENT arm rather than the same
    /// one: the created-coin leg is otherwise `ProvablyDead`, the funding-coin leg otherwise
    /// `Waiting`. A fixture whose honest answer already matched the mutant's could not see it.
    #[test]
    fn a_failed_coin_read_is_unknown_on_either_coin_and_never_an_absent_coin() {
        let flight = InFlight {
            funding_coin_id: coin_id(2),
            created_coin_id: coin_id(3),
            pushed_at_height: PUSHED_AT,
        };

        // The created coin cannot be read, and the funding coin is spent. Swallowing the error
        // reports ProvablyDead about a mint nobody has evidence about.
        let created_unreadable = OneCoinFails {
            failing: coin_id(3),
            records: vec![(coin_id(2), spent_at(coin_id(2), PUSHED_AT + 3))],
        };
        assert_eq!(
            flight.read(&created_unreadable),
            MintLiveness::Unknown,
            "an unreadable mint coin was treated as an absent one, which is the death test's whole \
             second half"
        );

        // The funding coin cannot be read, and the mint's own coin is absent. Swallowing the error
        // reports Waiting for a mint whose funding coin may already be spent elsewhere.
        let funding_unreadable = OneCoinFails {
            failing: coin_id(2),
            records: Vec::new(),
        };
        assert_eq!(
            flight.read(&funding_unreadable),
            MintLiveness::Unknown,
            "an unreadable funding coin was treated as an unspent one"
        );

        // Control: the SAME shapes with every read answering. Both reach a real, non-Unknown arm, so
        // an implementation returning `Unknown` whenever a coin is missing cannot pass.
        let answers = MockChainSource::new()
            .with_peak(PEAK)
            .with_coin(coin_id(2), spent_at(coin_id(2), PUSHED_AT + 3));
        assert_eq!(
            flight.read(&answers),
            MintLiveness::ProvablyDead {
                evidence: DeathEvidence {
                    funding_coin_id: coin_id(2),
                    funding_spent_at: PUSHED_AT + 3,
                    absent_did_coin_id: coin_id(3),
                }
            }
        );
    }

    /// A session holding exactly one journalled mint at `ix`, in `stage`.
    fn session_minting(ix: dig_account::ProfileIx, stage: MintStage) -> ProfileSession {
        let session = session_with(&[(dig_account::ProfileIx::ROOT, Some("first"))]);
        session
            .with_journal(|registry| {
                registry
                    .begin_seeded_mint(ix, stage, [0x44; 32], 10_000_000)
                    .map_err(|why| MintError::Journal(why.to_string()))
            })
            .expect("the fixture journals one mint");
        session
    }

    /// The pending record a pushed DID half journals: it spends wallet coin 2 to create DID coin 3.
    fn did_pending() -> PendingMintRecord {
        PendingMintRecord {
            launcher_id: coin_id(1),
            did_coin_id: coin_id(3),
            source_coin_id: coin_id(2),
            pushed_at_height: PUSHED_AT,
        }
    }

    /// The record of a DID that has CONFIRMED at coin 3 — the input the store half spends.
    ///
    /// The DID string is DERIVED from the launcher id rather than written out: the registry rejects
    /// a journal whose DID does not belong to its launcher, which is a rule this fixture must obey
    /// rather than route around.
    fn confirmed_did() -> MintedDidRecord {
        MintedDidRecord {
            did: dig_did::did_string_from_launcher_id(coin_id(1)),
            launcher_id: coin_id(1),
            coin_id: coin_id(3),
            confirmed_height: PUSHED_AT,
        }
    }

    /// **`liveness_of` reads the coins of the stage that is actually in the air, and reports nothing
    /// for the stage that is waiting on this host.**
    ///
    /// Makes impossible: swapping the two coin ids in the `StorePushed` arm. That swap keeps every
    /// `InFlight::read` test green, because those tests construct `InFlight` directly and never go
    /// through the arm that decides WHICH coin is which.
    ///
    /// # The one fixture that can see the swap, and why the obvious one cannot
    ///
    /// The store launch SPENDS the DID coin and CREATES the store coin. The fixture therefore has
    /// the DID coin spent and the store coin absent, which is provable death — some other spend took
    /// the DID coin, so this launch can never be included. Under the swap the same chain finds the
    /// DID coin present, concludes the bundle was included, and reports `Waiting` — leaving a user
    /// waiting indefinitely on a launch the chain can already prove is dead, with the evidence that
    /// would let them act withheld.
    ///
    /// The fixture that first suggested itself — a LIVE launch, store coin present — cannot see the
    /// swap at all: both readings find a coin and both answer `Waiting`. Only the asymmetric case,
    /// where exactly one of the two coins exists, distinguishes them.
    #[test]
    fn liveness_reads_the_coins_of_the_stage_that_is_in_the_air() {
        let ix = dig_account::ProfileIx(1);

        // The DID half is in the air: it spends coin 2 and would create coin 3.
        let did_pushed = session_minting(
            ix,
            MintStage::DidPushed {
                pending: did_pending(),
            },
        );
        let did_chain = MockChainSource::new()
            .with_peak(PEAK)
            .with_coin(coin_id(2), spent_at(coin_id(2), PUSHED_AT + 3));
        assert_eq!(
            liveness_of(&did_pushed, ix, &did_chain),
            Some(MintLiveness::ProvablyDead {
                evidence: DeathEvidence {
                    funding_coin_id: coin_id(2),
                    funding_spent_at: PUSHED_AT + 3,
                    absent_did_coin_id: coin_id(3),
                }
            }),
            "the DID stage's funding coin is the wallet coin it spends"
        );

        // The STORE half is in the air: it spends the DID coin (3) and would create the store coin
        // (5). The DID coin is gone and the store coin never appeared, so some OTHER spend consumed
        // the DID — this launch can never be included, exactly as in the DID stage.
        let store_pushed = session_minting(
            ix,
            MintStage::StorePushed {
                did: confirmed_did(),
                pending_store: PendingStoreLaunchRecord {
                    launcher_id: coin_id(4),
                    store_coin_id: coin_id(5),
                    did_coin_id: coin_id(3),
                    committed_root: [0x66; 32],
                    pushed_at_height: PUSHED_AT,
                },
            },
        );
        let store_chain = MockChainSource::new()
            .with_peak(PEAK)
            .with_coin(coin_id(3), spent_at(coin_id(3), PUSHED_AT + 3));
        assert_eq!(
            liveness_of(&store_pushed, ix, &store_chain),
            Some(MintLiveness::ProvablyDead {
                evidence: DeathEvidence {
                    funding_coin_id: coin_id(3),
                    funding_spent_at: PUSHED_AT + 3,
                    absent_did_coin_id: coin_id(5),
                }
            }),
            "the store stage's INPUT is the DID coin and its OUTPUT is the store coin; reading them \
             the other way round is the swap this fixture exists to catch"
        );

        // Nothing is on the network: the mint is waiting on THIS host, so there is no liveness.
        let paused = session_minting(
            ix,
            MintStage::DidConfirmedStoreNotLaunched {
                did: confirmed_did(),
            },
        );
        assert_eq!(
            liveness_of(&paused, ix, &store_chain),
            None,
            "a mint waiting on this host has no bundle in the air to report on"
        );

        // A profile with no journalled mint has no liveness either, whatever the chain says.
        assert_eq!(
            liveness_of(&did_pushed, dig_account::ProfileIx(7), &did_chain),
            None
        );
    }

    /// A publisher that RECORDS whether it was ever asked to push, and pushes nothing.
    ///
    /// The count is the load-bearing part: a refusal that happened after a bundle reached the
    /// network would be no refusal at all, and only "was `push` called?" can tell the difference.
    #[derive(Default)]
    struct RecordingPublisher {
        pushes: std::cell::Cell<usize>,
    }

    impl SpendPublisher for RecordingPublisher {
        fn push(
            &self,
            _bundle: &chia_protocol::SpendBundle,
        ) -> Result<dig_account::mint::PushOutcome, dig_account::mint::ChainUnavailable> {
            self.pushes.set(self.pushes.get() + 1);
            Err(dig_account::mint::ChainUnavailable::new(
                "this test publisher never reaches a network",
            ))
        }
    }

    /// **A mint is refused when the registry could not be READ, and the refusal is at the DOOR
    /// (dig-app#209).**
    ///
    /// A session whose registry failed to load runs on a `MemoryRegistryStore`. A mint there spends
    /// real XCH and creates a permanent on-chain identity whose only record is in memory, so the
    /// paid DID is gone on restart and `next_free_ix` then aims the following mint at an index that
    /// is already occupied. Money spent, and no durable record that it happened.
    ///
    /// # Why this asserts at the door and not at the card
    ///
    /// The fix is a PLACEMENT. A guard on the create control produces an identical observable — no
    /// mint happens — while leaving every non-surface caller of `begin` unguarded, so a test that
    /// only read `ProfileCreation` would pin a coincidence and stay green if the guard later moved
    /// back out to the surface. Asserting that `begin` itself refuses AND that `push` was never
    /// called is what makes the placement visible.
    ///
    /// # The control is the other half of the ticket, not decoration
    ///
    /// An ABSENT registry (`NotFound` → `ProfileRegistry::empty()`) is the ordinary first-run state
    /// and must NOT be blocked; blocking it would refuse every new user their first profile. So the
    /// same assertions run against an unprofiled session and must come out the other way. Without
    /// it, "always refuse" passes.
    #[test]
    fn an_unreadable_registry_refuses_the_mint_at_the_door_while_an_absent_one_does_not() {
        let residency = crate::test_support::test_residency();
        let publisher = RecordingPublisher::default();

        let unreadable = ProfileSession::unreadable("the registry file is not JSON");
        let door = ProfileMint::new(
            &unreadable,
            &residency,
            WalletSlot::unprofiled(),
            MintTarget::next_free(&ProfileRegistry::empty()),
            &WalksLineages,
            &publisher,
            MintNetwork::mainnet(),
            MintOptions::with_fee(0),
        );

        assert_eq!(
            Some(MintRefusal::RegistryUnreadable),
            door.account_refusal(),
            "a session that could not read its registry cannot record a mint"
        );
        assert!(
            door.checked_target().is_err(),
            "no index may be handed out for a mint that could not be journalled"
        );
        assert!(
            door.begin(&ProfileSeed::new().with_display_name("first"))
                .is_err(),
            "the DOOR refuses, so a caller that never touches the create control is guarded too"
        );
        assert_eq!(
            0,
            publisher.pushes.get(),
            "nothing may reach the network — a refusal after a push is not a refusal"
        );
        assert_eq!(
            ProfileCreation::Blocked(CreationBlocked::RegistryUnreadable),
            ProfileCreation::of_profile_mint(
                ProfileMintSeams::Wired { mint: &door }.availability()
            ),
            "and the surface names THIS cause, not the node's"
        );

        // The control: an absent registry is the ordinary first run and must still be offered.
        let absent = ProfileSession::unprofiled();
        let ordinary = ProfileMint::new(
            &absent,
            &residency,
            WalletSlot::unprofiled(),
            MintTarget::next_free(&ProfileRegistry::empty()),
            &WalksLineages,
            &publisher,
            MintNetwork::mainnet(),
            MintOptions::with_fee(0),
        );
        assert_eq!(
            None,
            ordinary.account_refusal(),
            "a first-run account has nothing wrong with it"
        );
        assert_eq!(
            Some(ProfileIx::ROOT),
            ordinary.checked_target().ok().map(MintTarget::ix),
            "and it is offered the index its pre-mint address was funded at"
        );
        assert_eq!(
            ProfileCreation::Possible,
            ProfileCreation::of_profile_mint(
                ProfileMintSeams::Wired { mint: &ordinary }.availability()
            )
        );
    }

    /// **An account with no free index is refused at the door, and told so (dig-app#263).**
    ///
    /// dig-account 0.22 made `next_free_ix` report exhaustion instead of saturating at an occupied
    /// ceiling. The property this pins is what the door does with that: it must refuse, and it must
    /// never substitute an index — a substituted index is one that may already hold a profile, which
    /// `record_minted` then refuses as a duplicate, permanently, from durable state.
    ///
    /// The ordinary account beside it is the control, for the reason given on the #209 test above.
    #[test]
    fn an_index_exhausted_account_is_refused_a_target_rather_than_given_an_occupied_one() {
        let residency = crate::test_support::test_residency();
        let publisher = RecordingPublisher::default();
        let session = session_with(&[(ProfileIx::ROOT, Some("home"))]);

        let door = ProfileMint::new(
            &session,
            &residency,
            WalletSlot::unprofiled(),
            // Exhaustion, expressed the only way it can be: no target at all.
            None,
            &WalksLineages,
            &publisher,
            MintNetwork::mainnet(),
            MintOptions::with_fee(0),
        );

        assert_eq!(Some(MintRefusal::IndexesExhausted), door.account_refusal());
        assert!(
            door.checked_target().is_err(),
            "the door must not invent an index for an account that has none"
        );
        assert!(door
            .begin(&ProfileSeed::new().with_display_name("another"))
            .is_err());
        assert_eq!(
            0,
            publisher.pushes.get(),
            "nothing may reach the network for a mint that could never be recorded"
        );
        assert_eq!(
            ProfileCreation::Blocked(CreationBlocked::IndexesExhausted),
            ProfileCreation::of_profile_mint(
                ProfileMintSeams::Wired { mint: &door }.availability()
            )
        );

        // The control: the SAME account with a free index is not refused, so the `None` above is a
        // statement about exhaustion rather than about this fixture.
        let ordinary = ProfileMint::new(
            &session,
            &residency,
            WalletSlot::unprofiled(),
            MintTarget::next_free(&ProfileRegistry::empty()),
            &WalksLineages,
            &publisher,
            MintNetwork::mainnet(),
            MintOptions::with_fee(0),
        );
        assert_eq!(None, ordinary.account_refusal());
    }

    /// **A `record` this session refused reports that the profile MAY BE FORGOTTEN (SEC-4).**
    ///
    /// `MintDoorError::may_be_forgotten` reads `persisted` alone, and it is the one question a
    /// surface must ask before telling somebody to try again. Reaching `record` means the caller
    /// holds evidence of a mint CONFIRMED on chain, so money has certainly moved; reporting
    /// `Written` for a write that never happened would tell the warning surface the record is safe,
    /// and a person could pay a second time for an identity they already own.
    ///
    /// # What this reaches, stated rather than implied
    ///
    /// It calls [`unrecorded`] — the function `record`'s only `Err` arm calls — rather than
    /// rebuilding the error, which would assert nothing but its own construction. `record` itself is
    /// unreachable from any test, because its evidence types have no public constructor outside
    /// dig-account; that is deliberate and is the same property that stops a DID being recorded
    /// without on-chain proof. So the link between this rule and its call site is one direct call.
    ///
    /// The control is the second half: `may_be_forgotten` must not simply always be true, or the
    /// first assertion is about the predicate rather than about this error.
    #[test]
    fn a_record_refused_by_the_session_reports_that_the_profile_may_be_forgotten() {
        let fault = unrecorded(MintError::Refused(copy_registry_unreadable()));
        assert!(
            fault.may_be_forgotten(),
            "a confirmed profile that reached no disk was reported as saved: {fault}"
        );
        assert!(
            fault.to_string().contains("reached no disk"),
            "the refusal must name what did not happen: {fault}"
        );

        let written = MintDoorError {
            mint: Some(MintError::Refused("something else".to_string())),
            persisted: PersistOutcome::Written,
        };
        assert!(
            !written.may_be_forgotten(),
            "the predicate must be capable of answering false, or the assertion above is vacuous"
        );
    }
}
