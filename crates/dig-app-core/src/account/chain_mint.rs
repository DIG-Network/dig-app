//! The REAL DID mint: dig-account's [`ProfileMinter`](dig_account::ProfileMinter) behind the wizard's
//! seams (dig_ecosystem#2359).
//!
//! [`crate::account::mint`] describes the wizard's shape — submit, then WAIT, and only a confirmation
//! may be recorded. This module is what makes that shape spend real money: it turns
//! [`begin_did_mint`](dig_account::ProfileMinter::begin_did_mint) into a [`Submission`] and
//! [`mint_status`](dig_account::ProfileMinter::mint_status) into a
//! [`Sighting`], so the wizard's tested flow is unchanged and the chain is what answers it.
//!
//! # Why the minter is derived per call and never held
//!
//! [`ChainMint`] holds the [`AccountResidency`], not a `ProfileMinter`. dig-account 0.6.0 makes
//! `UnlockedAccount::profile_minter` the single door to a minter, precisely so the spending capability
//! observes the unlock — and this module keeps that property whole by never retaining one across a
//! call. A locked account therefore has no minter at all, rather than a live one that refuses.
//!
//! # The two halves of the chain, and why they are separate seams
//!
//! Reading (`ChainSource`) and pushing ([`SpendPublisher`]) are different capabilities and dig-account
//! keeps them apart: the canonical read trait deliberately cannot broadcast. This module takes one of
//! each, so a host can supply a reader with no way to spend.
//!
//! # What this module still cannot do, and exactly which read is missing
//!
//! **The two absent control methods recorded here through 10.1.x now EXIST, and the paragraphs that
//! called them absent were true only of dig-node 0.109.0 and earlier.** dig-node **0.110.0** serves
//! `control.wallet.coinSpend` and `control.wallet.coinsByParent`, both OPEN reads, and
//! `dig-node-control-interface` **0.10** declares them. dig-app now has a concrete client for all
//! five reads plus the push — [`crate::chain::ControlChainSource`] and
//! [`crate::chain::ControlSpendPublisher`] (dig_ecosystem#2560).
//!
//! A profile is a DID **plus** a dig-store launched from that DID's coin; a DID is never minted
//! alone. `dig_account::ProfileMinter::advance_profile_mint` resolves the second half through
//! `launch_store`, which re-derives the DID's puzzle material from chain with
//! `dig_did::walk_did_lineage_to_tip`. That walk calls `ChainSource::resolve_singleton_lineage` and
//! then `ChainSource::parent_spend`, which composes `coin_record` with `coin_spend`. So the reads a
//! whole profile needs are five, not four:
//!
//! | Read | Control method | dig-node 0.110.0 | dig-app client |
//! |---|---|---|---|
//! | `peak_height` | `control.wallet.peak` | answers | built |
//! | `coin_record` | `control.wallet.coinById` | answers | built |
//! | `coin_records_by_puzzle_hash(ph, false)` | `control.wallet.coins` | answers (address-scoped, unspent-only) | built |
//! | `coin_spend` | `control.wallet.coinSpend` | answers | built |
//! | `resolve_singleton_lineage` | *(composed from `coinsByParent`)* | answers the hop | **not built** |
//!
//! **The ONE remaining gap is the lineage walk, and it is deliberate.** A coin's puzzle hash is
//! attacker-chosen, so authenticating a singleton means walking real recreation spends — and
//! `dig-chainsource-interface` ships exactly one hardened `walk_singleton_lineage` for the
//! whole ecosystem to share. Until it publishes, [`crate::chain::ControlChainSource`] returns a
//! marked `Unsupported` there (dig_ecosystem#2572) rather than a second hand-rolled walk.
//!
//! **Why that is still a STOP and not a degradation.** The four reads that ARE built are exactly
//! enough to push the DID half and watch it confirm. Phase B would then fail on every attempt with
//! `ChainUnreachable`, leaving the user at `ProfileMintStatus::DidConfirmedStoreNotLaunched` —
//! which dig-account itself calls "the state that costs money to get wrong": funds committed, an
//! identity on chain, and no profile, permanently. Shipping a seam that reaches that state is worse
//! than shipping none, so the binary keeps [`MintSeams::NoChainTransport`] and the startup gate asks
//! whether a mint is POSSIBLE before it shows anybody a wizard: see
//! [`crate::account::journey::startup_wizard`]. Wiring these seams in is a later stage of
//! dig_ecosystem#2398, gated on that walk.

use std::sync::Mutex;

use dig_account::mint::{
    ChainUnavailable, MintError, MintNetwork, MintOptions, MintStatus, PendingMint, PushOutcome,
    SpendPublisher,
};
use dig_chainsource_interface::ChainSource;

use crate::account::active_profile::{MintTarget, WalletSlot};
use crate::account::did::MintEvidence;
use crate::account::mint::{DidMinter, MintObserver, Sighting, Submission, UnavailableMinter};
use crate::account::residency::AccountResidency;
use crate::chain::{AbsenceWarrant, AbsenceWitness};

/// Whether this build can mint a DID at all.
///
/// Modelled as a value rather than left implicit because it decides whether the startup wizard is
/// shown: a wizard offered to somebody whose app cannot mint is the dead end dig_ecosystem#1800
/// removed, and one withheld from somebody whose app CAN mint is the gap dig_ecosystem#2359 opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintAvailability {
    /// A chain reader and a publisher are both wired, so a mint can be attempted.
    Possible,
    /// This build has no way to read coins or push a bundle, so no mint can be attempted on any
    /// account. Distinct from a wallet that merely has no funds — that one the user can fix.
    NoChainTransport,
}

/// The DID-minting seams a build actually has — and the ONLY source of a [`MintAvailability`].
///
/// # Why this type exists (dig_ecosystem#2377)
///
/// The gate and the minter used to be separate expressions: a free-standing `mint_availability()`
/// returned a constant, while the wizard was handed its minter somewhere else entirely. Flipping
/// that constant to [`MintAvailability::Possible`] in ONE line therefore opened an undismissible
/// wizard whose only forward control answered "not available in this version" — the dead end
/// dig_ecosystem#1800 removed — and, on the same line, made the app ask for a password at start-up.
/// Neither was catchable by a test, because both lived in the binary.
///
/// Here the two cannot disagree, because they are the same value: the availability is READ OFF the
/// seams, and obtaining a `Possible` means having constructed a real minter to read it from. A build
/// with no chain transport has no `Wired` variant to name.
pub enum MintSeams<'a> {
    /// A real minter and the observer that can see what it pushed.
    Wired {
        /// Builds, signs and pushes the mint spend.
        minter: &'a dyn DidMinter,
        /// Watches the chain for the pushed spend's confirmation.
        observer: &'a dyn MintObserver,
    },
    /// This build has no way to read coins or push a bundle, so nothing on this machine can mint.
    NoChainTransport,
}

impl MintSeams<'_> {
    /// Whether a mint can be attempted at all — derived from the seams, never asserted beside them.
    pub fn availability(&self) -> MintAvailability {
        match self {
            MintSeams::Wired { .. } => MintAvailability::Possible,
            MintSeams::NoChainTransport => MintAvailability::NoChainTransport,
        }
    }

    /// The minter the wizard should use. Without a transport this is the one that refuses honestly,
    /// so a wizard reached by any other route still cannot fabricate a spend.
    pub fn minter(&self) -> &dyn DidMinter {
        match self {
            MintSeams::Wired { minter, .. } => *minter,
            MintSeams::NoChainTransport => &UnavailableMinter,
        }
    }

    /// The observer the wizard should watch with, paired with [`minter`](Self::minter).
    pub fn observer(&self) -> &dyn MintObserver {
        match self {
            MintSeams::Wired { observer, .. } => *observer,
            MintSeams::NoChainTransport => &UnreachableChain,
        }
    }
}

/// The observer a build with no transport gets: it can never look, and says so.
///
/// Lives beside [`MintSeams`] rather than in the binary so the transport-less pairing is one value
/// a test can hold, rather than two constants a shell assembles by hand.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnreachableChain;

impl MintObserver for UnreachableChain {
    fn look(&self, _spend_id: &str) -> Sighting {
        Sighting::Unreachable
    }
}

/// Mints a DID through dig-account, against an injected chain reader and publisher.
///
/// Implements BOTH wizard seams — [`DidMinter`] and [`MintObserver`] — because the two are one
/// conversation with the chain: the [`PendingMint`] the push produced is what a status poll must be
/// asked about, and it is remembered here rather than flattened into the spend-id string the wizard
/// passes around.
pub struct ChainMint<'a, C: ?Sized, P: ?Sized> {
    /// The live account. A minter is derived from it per call and never retained (module docs).
    residency: &'a AccountResidency,
    /// The profile whose wallet PAYS for the mint.
    funding: WalletSlot,
    /// The index the new profile's keys will derive at.
    ///
    /// Separate from [`funding`](Self::funding) deliberately: they are the same only while an account
    /// has at most one profile, and collapsing them makes the first second-profile mint try to fund
    /// itself from the brand-new profile's empty wallet. See [`MintTarget`].
    target: MintTarget,
    /// Reads coins, spends and the peak. Cannot broadcast, by construction.
    chain: &'a C,
    /// Pushes the signed bundle. Never sees a key.
    publisher: &'a P,
    /// Which network's `AGG_SIG_ME` domain the mint signs under.
    network: MintNetwork,
    /// The farmer fee, bounded by dig-account's own `MAX_MINT_FEE_MOJOS`.
    options: MintOptions,
    /// The mint this instance pushed, if it pushed one. The only thing `mint_status` can be asked about.
    pending: Mutex<Option<PendingMint>>,
}

impl<'a, C, P> ChainMint<'a, C, P>
where
    C: ChainSource + ?Sized,
    P: SpendPublisher + ?Sized,
{
    /// A minter that pays from `funding`'s wallet and creates the profile at `target`, reading
    /// through `chain` and pushing through `publisher`.
    ///
    /// # Money
    ///
    /// With [`MintNetwork::mainnet`] this spends real XCH the moment [`DidMinter::submit`] is called.
    pub fn new(
        residency: &'a AccountResidency,
        funding: WalletSlot,
        target: MintTarget,
        chain: &'a C,
        publisher: &'a P,
        network: MintNetwork,
        options: MintOptions,
    ) -> Self {
        Self {
            residency,
            funding,
            target,
            chain,
            publisher,
            network,
            options,
            pending: Mutex::new(None),
        }
    }

    /// The mint this instance pushed, if any.
    fn remembered(&self) -> Option<PendingMint> {
        self.guard().clone()
    }

    /// The pending-mint slot. A poisoned lock means a thread panicked mid-mint — custody state whose
    /// half-updated form must not be reused, so this fails loudly rather than quietly.
    fn guard(&self) -> std::sync::MutexGuard<'_, Option<PendingMint>> {
        self.pending
            .lock()
            .expect("chain-mint pending lock poisoned")
    }
}

impl<C, P> DidMinter for ChainMint<'_, C, P>
where
    C: ChainSource + ?Sized,
    P: SpendPublisher + ?Sized,
{
    fn submit(&self) -> Submission {
        // ALREADY DONE. A second push would spend a second fee, create a second DID, and overwrite
        // the pending slot -- which would make the FIRST mint unobservable, so the money would be
        // gone with no DID ever recorded (dig_ecosystem#2377). The wizard's copy asks the person not
        // to do this three separate times; this is that request as an invariant.
        if let Some(pending) = self.remembered() {
            return Submission::Refused {
                reason: format!(
                    "This DIG Account has already paid for a mint ({}). Wait for it to confirm \
                     rather than paying again.",
                    pending.pending_did_string()
                ),
            };
        }

        // Derived here, per call. A locked account produces no minter, so a mint attempted after a
        // lock-now or an idle timeout cannot even be built (module docs).
        let Some(minter) = self.residency.profile_minter() else {
            return Submission::Refused {
                reason: "Your DIG Account is locked. Unlock it and try again.".to_owned(),
            };
        };

        // `begin_did_mint` mints at `ix` AND funds from that same index's wallet, so it cannot
        // express a mint paid for by one profile and created at another. That is invisible for the
        // FIRST profile, where the two indices coincide at ROOT. Refuse the divergent case loudly
        // rather than paying from a wallet the user did not intend or minting at the wrong index.
        //
        // This used to cite dig_ecosystem#2496 as a pending upstream. It SHIPPED in dig-account 0.13
        // and is closed — `wallet_ops_at(ix)` exists. It does not dissolve this refusal: deriving a
        // wallet at an index is not the same as dig-account's ceremony accepting a funding index
        // that differs from its target, which it still does not. A SECOND profile therefore hits
        // this message, and the message IS the remedy: fund the target's address first.
        if self.funding.ix() != self.target.ix() {
            return Submission::Refused {
                reason: format!(
                    "This mint would pay from profile {} but create profile {}, and DIG cannot yet \
                     fund one profile's mint from another's wallet. Move funds to profile {}'s \
                     address first.",
                    self.funding, self.target, self.target
                ),
            };
        }

        match minter.begin_did_mint(
            self.target.ix(),
            self.chain,
            self.publisher,
            &self.network,
            &self.options,
        ) {
            Ok(pending) => {
                let submitted = Submission::Submitted {
                    spend_id: hex_id(pending.did_coin_id()),
                    // The DID this mint WILL have. It is not evidence and is never recorded from
                    // here — the ledger is written from the CONFIRMED sighting's own DID.
                    did: pending.pending_did_string(),
                };
                *self.guard() = Some(pending);
                submitted
            }
            Err(e) => submission_failure(e),
        }
    }
}

impl<C, P> MintObserver for ChainMint<'_, C, P>
where
    C: ChainSource + AbsenceWitness + ?Sized,
    P: SpendPublisher + ?Sized,
{
    fn look(&self, spend_id: &str) -> Sighting {
        // Asked about a mint this instance did not push -- either because it pushed nothing, or
        // because the id names a DIFFERENT spend. Both are the same fact and get the same answer:
        // this observer cannot look. Comparing the id rather than merely checking that SOMETHING was
        // pushed is what makes the guard match its own rationale (dig_ecosystem#2377); without it,
        // asking about somebody else's spend returned this mint's status under their name.
        let pending = match self.remembered() {
            Some(pending) if hex_id(pending.did_coin_id()) == spend_id => pending,
            _ => {
                // Reported as unreachable rather than as a rejection: nothing here knows the spend
                // failed, only that it cannot be looked up.
                tracing::warn!(%spend_id, "asked about a mint this minter did not push");
                return Sighting::Unreachable;
            }
        };

        let Some(minter) = self.residency.profile_minter() else {
            // A locked account cannot read its own mint. The spend is on the chain regardless, so
            // this is a lost look, never a failed mint.
            return Sighting::Unreachable;
        };

        match minter.mint_status(&pending, self.chain) {
            Ok(MintStatus::Confirmed(minted)) => Sighting::Confirmed {
                // Both the DID and the evidence come from the CONFIRMATION, never from the push.
                did: minted.did().to_owned(),
                evidence: MintEvidence::confirmed(
                    hex_id(minted.coin_id()),
                    minted.confirmed_height(),
                ),
            },
            Ok(MintStatus::Awaiting { .. }) => Sighting::Pending,
            // A failure verdict rests ENTIRELY on an absence. dig-account reaches it from
            // `did_record.is_none()` beside a spent funding coin (`mint/did.rs:240`) — a conclusion
            // that is only sound if the source could see the DID coin had it existed. From a tier
            // that admits it is behind, the same two reads describe a mint that DID confirm and a
            // replica that has not caught up with it, and telling that person their identity can
            // never exist is the falsehood about custody dig_ecosystem#2919 exists to stop.
            //
            // So the verdict is believed only against a warrant, and otherwise degrades to the
            // UNKNOWN the chain actually gave us. Unknown is survivable — the watch keeps looking
            // and can still confirm — while a wrong rejection is permanent and unrecoverable.
            Ok(MintStatus::Failed { reason }) => match self.chain.absence_warrant() {
                AbsenceWarrant::Warranted => Sighting::Rejected { reason },
                AbsenceWarrant::Withheld { because } => {
                    tracing::warn!(
                        %spend_id,
                        %reason,
                        %because,
                        "refusing to report a mint as failed on an absence the source cannot warrant"
                    );
                    Sighting::Unreachable
                }
            },
            // A chain that could not answer says nothing about the spend, so it can only ever be an
            // unreachable look. Collapsing it into a rejection would tell a user their mint failed
            // because their wifi dropped.
            Err(MintError::ChainUnreachable(_)) => Sighting::Unreachable,
            Err(e) => Sighting::Rejected {
                reason: e.to_string(),
            },
        }
    }
}

/// Turn a failed `begin_did_mint` into the wizard's own vocabulary.
///
/// The three endings a person can act on differently get their own [`Submission`] variants; every
/// other failure is a refusal carrying dig-account's own words, which the wizard shows verbatim.
fn submission_failure(error: MintError) -> Submission {
    match error {
        MintError::InsufficientFunds { required, .. } => Submission::InsufficientFunds {
            needed: xch(required),
        },
        MintError::Locked => Submission::Refused {
            reason: "Your DIG Account locked before the mint could be signed.".to_owned(),
        },
        other => Submission::Refused {
            reason: other.to_string(),
        },
    }
}

/// A mojo amount as XCH, for a sentence a person reads.
///
/// Twelve decimal places is the full precision of a mojo and unreadable, so trailing zeros are
/// dropped — but never the leading digit, and never rounded UP: a shortfall reported as smaller than
/// it is would send somebody to fund an amount that still does not cover the mint.
///
/// It DELEGATES to [`crate::amount::format_units`], which is the crate's one mojos-to-XCH conversion
/// (dig_ecosystem#2957); this function only appends the unit. It used to divide by its own
/// `MOJOS_PER_XCH` constant, which made it a second implementation of the same arithmetic — and this crate has put a
/// money figure on screen through the wrong divisor twice (a `$DIG` row using the CAT divisor,
/// dig_ecosystem#2879, and a send dialog reading 50,000,000 mojos out as `50000000 XCH`), both times
/// because a second conversion existed for a test to agree with.
pub(crate) fn xch(mojos: u64) -> String {
    format!(
        "{} XCH",
        crate::amount::format_units(u128::from(mojos), crate::amount::XCH_DECIMALS)
    )
}

/// A 32-byte chain id as lowercase hex with the `0x` prefix every Chia explorer uses.
fn hex_id(id: chia_protocol::Bytes32) -> String {
    format!("0x{}", hex::encode(id))
}

/// The publisher a build with no transport gets: it can never push, and says so.
///
/// Deliberately NOT a silent success. A publisher that reported [`PushOutcome::Accepted`] without
/// pushing would send the wizard into a wait for a bundle that never left this computer.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoPublisher;

impl SpendPublisher for NoPublisher {
    fn push(&self, _bundle: &chia_protocol::SpendBundle) -> Result<PushOutcome, ChainUnavailable> {
        Err(ChainUnavailable::new(
            "this build has no way to broadcast a spend",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mojos in one XCH, DERIVED from the crate's decimal count rather than written out again — the
    /// production code no longer holds this constant, because it no longer does the division.
    const MOJOS_PER_XCH: u64 = 10u64.pow(crate::amount::XCH_DECIMALS);
    use chia_protocol::CoinSpend;
    use chia_protocol::{Bytes32, Coin, SpendBundle};
    use chia_sdk_test::Simulator;
    use dig_account::mint::MIN_CONFIRMATION_DEPTH;
    use dig_chainsource_interface::{
        ChainSourceError, CoinRecord, MockChainSource, SingletonLineage,
    };
    use std::cell::RefCell;

    /// The chain's peak in every fixture. A plausible mainnet height, so nothing passes because the
    /// numbers are small.
    const PEAK: u32 = 5_412_009;

    /// Enough to pay the singleton mojo and the fee several times over.
    const FUNDED_MOJOS: u64 = 100_000_000;

    /// A fee well under dig-account's `MAX_MINT_FEE_MOJOS` ceiling.
    const FEE: u64 = 5_000_000;

    /// A publisher that accepts, and records what it was handed.
    #[derive(Default)]
    struct RecordingPublisher {
        pushed: RefCell<Vec<SpendBundle>>,
    }

    impl SpendPublisher for RecordingPublisher {
        fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome, ChainUnavailable> {
            self.pushed.borrow_mut().push(bundle.clone());
            Ok(PushOutcome::Accepted)
        }
    }

    impl RecordingPublisher {
        /// How many bundles reached the network — the count a refusal must leave at zero.
        fn pushes(&self) -> usize {
            self.pushed.borrow().len()
        }
    }

    /// A publisher whose network answered "no".
    struct RejectingPublisher;

    impl SpendPublisher for RejectingPublisher {
        fn push(&self, _bundle: &SpendBundle) -> Result<PushOutcome, ChainUnavailable> {
            Ok(PushOutcome::Rejected {
                reason: "DOUBLE_SPEND".to_owned(),
            })
        }
    }

    fn options() -> MintOptions {
        MintOptions::with_fee(FEE)
    }

    /// A mock chain is the WHOLE chain in a test: there is no replica behind a truth it cannot see,
    /// so its absences are the chain's own. Stated rather than derived, because a double that
    /// withheld a warrant would turn every unrelated mint test into an unreachable look.
    impl AbsenceWitness for MockChainSource {
        fn absence_warrant(&self) -> AbsenceWarrant {
            AbsenceWarrant::Warranted
        }
    }

    /// Likewise for the consensus simulator, which is authoritative by construction.
    impl AbsenceWitness for SimulatorChain {
        fn absence_warrant(&self) -> AbsenceWarrant {
            AbsenceWarrant::Warranted
        }
    }

    /// A chain on which the mint's FUNDING coin gets spent by somebody else, with a warrant this
    /// fixture chooses.
    ///
    /// This is the one situation dig-account turns into [`MintStatus::Failed`]: the DID coin absent
    /// beside a funding coin that is spent (`dig-account 0.20.0 src/mint/did.rs:240`). Everything
    /// else delegates to the inner mock, so the mint really is built, signed and remembered by the
    /// ordinary path — only the two reads the VERDICT rests on are staged.
    ///
    /// `stolen` is a latch rather than a constructor argument because the funding coin must read
    /// UNSPENT while the bundle is built and SPENT afterwards; a chain that was already stolen at
    /// construction would refuse the mint for insufficient funds and never reach a verdict at all.
    struct FundingStolen<'a> {
        inner: &'a MockChainSource,
        funding: Coin,
        stolen: std::cell::Cell<bool>,
        /// What this source discloses about its own currency. The ONLY thing that differs between
        /// the control and the abuse case.
        warrant: AbsenceWarrant,
    }

    impl<'a> FundingStolen<'a> {
        fn new(inner: &'a MockChainSource, funding: Coin, warrant: AbsenceWarrant) -> Self {
            Self {
                inner,
                funding,
                stolen: std::cell::Cell::new(false),
                warrant,
            }
        }

        /// Somebody else's spend takes the funding coin, after this mint was already pushed.
        fn steal(&self) {
            self.stolen.set(true);
        }
    }

    impl ChainSource for FundingStolen<'_> {
        type Error = ChainSourceError;

        fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            if self.stolen.get() && coin_id == self.funding.coin_id() {
                return Ok(Some(CoinRecord {
                    coin: self.funding,
                    confirmed_height: Some(PEAK - 100),
                    spent_height: Some(PEAK),
                    timestamp: None,
                    coinbase: false,
                }));
            }
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

        fn coin_records_by_parent(&self, parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
            self.inner.coin_records_by_parent(parent)
        }

        fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
            self.inner.coin_spend(coin_id)
        }

        fn resolve_singleton_lineage(
            &self,
            launcher_id: Bytes32,
        ) -> Result<Option<SingletonLineage>, Self::Error> {
            self.inner.resolve_singleton_lineage(launcher_id)
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            self.inner.peak_height()
        }

        fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
            self.inner.block_timestamp(height)
        }
    }

    impl AbsenceWitness for FundingStolen<'_> {
        fn absence_warrant(&self) -> AbsenceWarrant {
            self.warrant.clone()
        }
    }

    /// Push a real mint, then let somebody else take the funding coin, and report what the watcher
    /// sees through a source disclosing `warrant`.
    fn verdict_on_a_stolen_funding_coin(warrant: AbsenceWarrant) -> Sighting {
        let bench = Bench::funded();
        let inner = bench.chain();
        let chain = FundingStolen::new(&inner, bench.funding, warrant);
        let publisher = RecordingPublisher::default();
        let minter = bench.mint(&chain, &publisher);

        let Submission::Submitted { spend_id, .. } = minter.submit() else {
            panic!("a funded, unlocked account must be able to push a mint");
        };
        chain.steal();
        minter.look(&spend_id)
    }

    /// **CONTROL — a source that CAN warrant its absences still reports a real failure as a
    /// failure.** Without this the guard below is satisfied by a bridge that never rejects anything,
    /// and "unknown" would have quietly replaced every verdict the user needs to act on.
    #[test]
    fn a_warranted_absence_still_yields_a_rejection() {
        let Sighting::Rejected { reason } =
            verdict_on_a_stolen_funding_coin(AbsenceWarrant::Warranted)
        else {
            panic!("a synced source reporting a stolen funding coin must reject the mint");
        };
        assert!(
            reason.contains("can never confirm"),
            "the rejection carries dig-account's own words: {reason}"
        );
    }

    /// **A verdict of FAILURE is refused when the source cannot warrant the absence it rests on**
    /// (dig_ecosystem#2919).
    ///
    /// Identical to the control in every respect except what the source discloses about its own
    /// currency — same account, same funding coin, same push, same stolen coin, same
    /// `MintStatus::Failed` out of dig-account. Before the guard, both cases returned
    /// `Rejected`, telling somebody whose mint may well have confirmed that their identity can never
    /// exist. Real XCH spent, a permanent on-chain DID, reported as dead.
    ///
    /// It must read as UNREACHABLE and not as pending: pending asserts the mint is still in flight,
    /// which is a claim this source is equally unable to make.
    #[test]
    fn an_unwarranted_absence_cannot_produce_a_failure_verdict() {
        assert_eq!(
            verdict_on_a_stolen_funding_coin(AbsenceWarrant::Withheld {
                because: "the tier that answered reported synced=false".to_owned(),
            }),
            Sighting::Unreachable,
            "a source that admits it may be behind cannot say a DID does not exist"
        );
    }

    /// A confirmed, unspent record of `coin` at `height`.
    fn confirmed(coin: Coin, height: u32) -> CoinRecord {
        CoinRecord {
            coin,
            confirmed_height: Some(height),
            spent_height: None,
            timestamp: None,
            coinbase: false,
        }
    }

    /// A whole account plus the chain its wallet lives on — assembled together because the mint's
    /// funding coin has to sit at the puzzle hash THIS account derives, and a fixture that guessed
    /// one would simply report "insufficient funds" for every test in the module.
    struct Bench {
        residency: AccountResidency,
        puzzle_hash: Bytes32,
        funding: Coin,
    }

    impl Bench {
        /// An unlocked account whose wallet holds one confirmed coin large enough to mint from.
        fn funded() -> Self {
            let residency = crate::account::residency::test_support::residency();
            let puzzle_hash = residency
                .wallet_puzzle_hash_for_test()
                .expect("a fresh residency is unlocked");
            Self {
                funding: Coin::new(Bytes32::new([7; 32]), puzzle_hash, FUNDED_MOJOS),
                puzzle_hash,
                residency,
            }
        }

        /// The chain as it stands before the mint: the peak, and the wallet's one spendable coin.
        fn chain(&self) -> MockChainSource {
            MockChainSource::new()
                .with_peak(PEAK)
                .with_coin(self.funding.coin_id(), confirmed(self.funding, PEAK - 100))
        }

        /// The same chain with the wallet holding NOTHING — the shortfall case.
        fn empty_chain(&self) -> MockChainSource {
            MockChainSource::new().with_peak(PEAK)
        }

        fn mint<'a, C: ChainSource + ?Sized, P: SpendPublisher + ?Sized>(
            &'a self,
            chain: &'a C,
            publisher: &'a P,
        ) -> ChainMint<'a, C, P> {
            ChainMint::new(
                &self.residency,
                WalletSlot::unprofiled(),
                MintTarget::next_free(&dig_account::registry::ProfileRegistry::empty())
                    .expect("a fixture registry is never index-exhausted"),
                chain,
                publisher,
                // A pinned test network rather than mainnet: the signatures are checked against these
                // constants, and naming mainnet in a unit test invites somebody to point it at one.
                // TESTNET11's constants, because the simulator validates against them: a bundle
                // signed under mainnet's AGG_SIG_ME domain verifies nowhere else.
                MintNetwork::from_constants(chia_sdk_signer::AggSigConstants::from(
                    &*chia_wallet_sdk::prelude::TESTNET11_CONSTANTS,
                )),
                options(),
            )
        }

        /// A minter whose funding and target indices DISAGREE — the second-profile mint.
        fn mint_funded_by_another_profile<
            'a,
            C: ChainSource + ?Sized,
            P: SpendPublisher + ?Sized,
        >(
            &'a self,
            chain: &'a C,
            publisher: &'a P,
        ) -> ChainMint<'a, C, P> {
            let registry = crate::account::profile_session::test_support::registry_with(&[(
                dig_account::ProfileIx::ROOT,
                None,
            )]);
            ChainMint::new(
                &self.residency,
                WalletSlot::from_active(
                    registry
                        .active()
                        .expect("the fixture has an active profile"),
                ),
                MintTarget::next_free(&registry)
                    .expect("a fixture registry is never index-exhausted"),
                chain,
                publisher,
                MintNetwork::from_constants(chia_sdk_signer::AggSigConstants::from(
                    &*chia_wallet_sdk::prelude::TESTNET11_CONSTANTS,
                )),
                options(),
            )
        }
    }

    /// **A mint whose funding and target indices differ is REFUSED, and pushes nothing**
    /// (dig_ecosystem#2398).
    ///
    /// dig-account 0.8's `begin_did_mint` mints at an index AND funds from that same index's wallet,
    /// so it cannot express a mint paid for by one profile and created at another
    /// (dig_ecosystem#2496). Passing the target index anyway would silently spend from a brand-new
    /// profile's empty wallet; passing the funding index would mint the second profile at the FIRST
    /// profile's index, which the registry cannot even represent.
    ///
    /// The control is what makes this load-bearing: the SAME residency and the SAME chain, with the
    /// two indices coinciding, submits for real. Without it a `submit` that refused everything would
    /// satisfy the refusal identically. `mint_status` is asserted afterwards because a refusal that
    /// had already pushed would leave real XCH spent and unobservable.
    #[test]
    fn a_mint_funded_by_a_different_profile_than_it_creates_is_refused() {
        let fixture = Bench::funded();
        let publisher = RecordingPublisher::default();

        let refused = fixture
            .mint_funded_by_another_profile(&fixture.chain(), &publisher)
            .submit();

        let Submission::Refused { reason } = refused else {
            panic!("a divergent funding/target mint must be refused: {refused:?}");
        };
        assert!(
            reason.contains("profile 0") && reason.contains("profile 1"),
            "the refusal must name BOTH indices so the remedy is actionable: {reason}"
        );
        assert_eq!(
            0,
            publisher.pushes(),
            "a refusal must push NOTHING — a pushed bundle is real XCH spent"
        );

        // Control: the same fixture, the same chain, indices coinciding — this really does submit.
        assert!(
            matches!(
                fixture.mint(&fixture.chain(), &publisher).submit(),
                Submission::Submitted { .. }
            ),
            "the control must genuinely submit, or the refusal above proves nothing"
        );
    }

    /// **A REAL mint runs end to end, validated by Chia consensus: a coin is selected, a bundle is
    /// built and signed, a full node's own CLVM + BLS verification accepts it, and the DID coin it
    /// creates becomes recorded evidence.**
    ///
    /// This is the proof dig_ecosystem#2359 asked for before any gate is wired. Nothing here is a
    /// double that agrees with the implementation: the bundle goes through
    /// [`chia_sdk_test::Simulator`], the same validator a full node runs, so a mint that confirms
    /// here is one whose puzzles and signatures are genuinely correct.
    ///
    /// The middle assertion is the load-bearing one. The simulator holds a pushed bundle in a
    /// MEMPOOL until a block is farmed, so there is a real window in which everything a naive
    /// implementation would call success has happened and no DID exists. A bridge that reported a
    /// confirmation from a push would pass every other assertion in this test and fail that one.
    #[test]
    fn a_did_mints_and_confirms_end_to_end() {
        let bench = Bench::funded();
        let chain = SimulatorChain::new();
        chain.fund(bench.puzzle_hash, FUNDED_MOJOS);
        let minter = bench.mint(&chain, &chain);

        let Submission::Submitted { spend_id, did } = minter.submit() else {
            panic!("a funded, unlocked account must be able to push a mint");
        };
        assert!(
            did.starts_with("did:chia:"),
            "the pending DID must be a real did:chia string: {did}"
        );

        // Pushed, in the mempool, not in a block. Still pending — never a success.
        assert_eq!(minter.look(&spend_id), Sighting::Pending);

        chain.farm();

        let Sighting::Confirmed {
            did: seen,
            evidence,
        } = minter.look(&spend_id)
        else {
            panic!("a farmed, buried mint must read as confirmed");
        };
        assert_eq!(seen, did, "the confirmed DID is the one this mint created");
        assert_eq!(
            evidence.spend_id(),
            hex_id(
                minter
                    .remembered()
                    .expect("a pushed mint is remembered")
                    .did_coin_id()
            ),
            "the evidence names the coin the bundle created"
        );
        assert!(
            evidence.confirmed_height() > 0,
            "a confirmation carries a real block height"
        );
    }

    /// **A second submit on the same minter must not spend again** (dig_ecosystem#2377).
    ///
    /// Before the guard, the second call pushed a SECOND real mint, paid a second fee, and
    /// overwrote `pending` — so the FIRST mint became unobservable: money spent, DID never
    /// recorded. The wizard's copy warns three separate times not to do this, which is copy
    /// standing in for an invariant.
    ///
    /// Two assertions, and the second is the load-bearing one. A guard that merely returned a
    /// refusal while still pushing would satisfy the first; only the PUBLISHER's own count can see
    /// whether a bundle left the machine. The fixture keeps the mint genuinely fundable throughout
    /// — the first submit succeeds — so this cannot pass because nothing could ever be pushed.
    #[test]
    fn a_second_submit_refuses_rather_than_spending_a_second_time() {
        let bench = Bench::funded();
        let chain = SimulatorChain::new();
        chain.fund(bench.puzzle_hash, FUNDED_MOJOS);
        let minter = bench.mint(&chain, &chain);

        let Submission::Submitted { spend_id, .. } = minter.submit() else {
            panic!("the first mint must go through");
        };
        let pushed_once = chain.pushed();

        let second = minter.submit();
        assert!(
            matches!(second, Submission::Refused { .. }),
            "a minter that already pushed must refuse; got {second:?}"
        );
        assert_eq!(
            chain.pushed(),
            pushed_once,
            "a second submit reached the network and spent again"
        );
        // ...and the FIRST mint is still the one this minter can be asked about.
        assert_eq!(
            hex_id(
                minter
                    .remembered()
                    .expect("the first mint is still remembered")
                    .did_coin_id()
            ),
            spend_id
        );
    }

    /// **`look` answers about THIS mint, not merely about "some mint I pushed"**
    /// (dig_ecosystem#2377).
    ///
    /// The guard's rationale is "did I push THIS spend", and before the fix the `spend_id` argument
    /// was ignored outside the log — so asking about somebody else's spend returned this instance's
    /// own status under the other spend's name. The fixture varies ONE thing: the id asked about,
    /// against a minter that genuinely did push, so a blanket `Unreachable` implementation is
    /// caught by the control assertion.
    #[test]
    fn a_look_at_a_different_spend_is_not_answered_from_this_one() {
        let bench = Bench::funded();
        let chain = SimulatorChain::new();
        chain.fund(bench.puzzle_hash, FUNDED_MOJOS);
        let minter = bench.mint(&chain, &chain);
        let Submission::Submitted { spend_id, .. } = minter.submit() else {
            panic!("the bench must be able to push");
        };

        assert_eq!(
            minter.look("0x0000000000000000000000000000000000000000000000000000000000000001"),
            Sighting::Unreachable,
            "a mint this instance did not push cannot be reported on"
        );
        assert_eq!(
            minter.look(&spend_id),
            Sighting::Pending,
            "the control: its OWN spend is still answerable"
        );
    }

    /// **An availability and the minter it describes cannot disagree** (dig_ecosystem#2377).
    ///
    /// The defect this replaces was a PLACEMENT: the gate lived in one expression and the minter in
    /// another, so a one-line edit to the gate produced a wizard that opened unbidden and could not
    /// be completed. A test asserting only "the gate says no" would have been satisfied by that
    /// arrangement identically.
    ///
    /// So this asserts the PAIRING, from both sides — the transport-less seams yield both
    /// `NoChainTransport` AND a minter that refuses, and a wired seam yields both `Possible` AND a
    /// minter that pushes. The second half is what keeps the first from passing trivially: with
    /// only the transport-less case, a `minter()` hardcoded to `UnavailableMinter` would pass.
    #[test]
    fn the_availability_and_the_minter_are_read_off_the_same_value() {
        let bench = Bench::funded();
        let chain = bench.chain();
        let publisher = RecordingPublisher::default();
        let real = bench.mint(&chain, &publisher);

        let absent = MintSeams::NoChainTransport;
        assert_eq!(absent.availability(), MintAvailability::NoChainTransport);
        assert_eq!(
            absent.minter().submit(),
            Submission::NotAvailable,
            "a build reported as having no transport must also be unable to spend"
        );

        let wired = MintSeams::Wired {
            minter: &real,
            observer: &real,
        };
        assert_eq!(wired.availability(), MintAvailability::Possible);
        assert!(
            matches!(wired.minter().submit(), Submission::Submitted { .. }),
            "a build reported as able to mint must have a minter that really can"
        );
    }

    /// A wallet with nothing in it reports a SHORTFALL, in XCH, rather than a generic refusal.
    ///
    /// The distinction matters because it is the one failure the person can actually act on — and it
    /// is why the startup gate must never trap somebody behind an unfunded wizard.
    #[test]
    fn an_unfunded_wallet_reports_what_the_mint_costs() {
        let bench = Bench::funded();
        let publisher = RecordingPublisher::default();
        let chain = bench.empty_chain();

        let Submission::InsufficientFunds { needed } = bench.mint(&chain, &publisher).submit()
        else {
            panic!("a wallet holding no coins cannot fund a mint");
        };
        assert!(
            needed.ends_with(" XCH"),
            "the shortfall must be readable: {needed}"
        );
        assert!(
            publisher.pushed.borrow().is_empty(),
            "nothing may be pushed when the mint cannot be funded"
        );
    }

    /// **A locked account cannot mint, and the lock is observed at the moment of the attempt.**
    ///
    /// The fixture locks a residency that WAS able to mint — proven by the end-to-end test above on
    /// the same construction — so this cannot pass merely because the bench is broken.
    #[test]
    fn a_locked_account_cannot_push_a_mint() {
        let bench = Bench::funded();
        let publisher = RecordingPublisher::default();
        let chain = bench.chain();
        let minter = bench.mint(&chain, &publisher);

        crate::session_lock::SessionKeys::lock_all(&bench.residency);

        assert!(matches!(minter.submit(), Submission::Refused { .. }));
        assert!(
            publisher.pushed.borrow().is_empty(),
            "a locked account must not reach the publisher at all"
        );
    }

    /// A network that ANSWERED "no" is a refusal carrying its reason — not a wait.
    #[test]
    fn a_rejected_push_is_refused_with_the_networks_reason() {
        let bench = Bench::funded();
        let chain = bench.chain();

        let Submission::Refused { reason } = bench.mint(&chain, &RejectingPublisher).submit()
        else {
            panic!("a rejected push is not a submission");
        };
        assert!(
            reason.contains("DOUBLE_SPEND"),
            "the network's words: {reason}"
        );
    }

    /// **A chain that cannot be reached is an unreachable LOOK, never a rejection.**
    ///
    /// The fixture keeps one honest actor — the mint really was pushed — and varies only the reader,
    /// so an implementation that collapsed every error into a rejection is caught. A fixture with no
    /// pushed mint could not see the difference, because it reports unreachable either way.
    #[test]
    fn a_chain_that_cannot_answer_is_not_a_rejection() {
        let bench = Bench::funded();
        let publisher = RecordingPublisher::default();
        let chain = bench.chain();
        let minter = bench.mint(&chain, &publisher);
        let Submission::Submitted { spend_id, .. } = minter.submit() else {
            panic!("the bench must be able to push");
        };

        let broken = bench
            .empty_chain()
            .fail_with(ChainSourceError::Transport("the network is down".into()));
        let blind = bench.mint(&broken, &publisher);
        *blind.guard() = minter.remembered();

        assert_eq!(blind.look(&spend_id), Sighting::Unreachable);
    }

    /// An observer asked about a mint it never pushed reports that it cannot look, rather than
    /// inventing an answer about somebody else's spend.
    #[test]
    fn a_minter_that_pushed_nothing_cannot_report_on_a_spend() {
        let bench = Bench::funded();
        let chain = bench.chain();
        let publisher = RecordingPublisher::default();

        assert_eq!(
            bench
                .mint(&chain, &publisher)
                .look("0xsomebody-elses-spend"),
            Sighting::Unreachable
        );
    }

    /// The shortfall renderer is exact at both ends: whole XCH stays whole, and a fractional amount
    /// keeps every significant digit rather than rounding a person short.
    #[test]
    fn a_mojo_amount_reads_as_xch() {
        assert_eq!(xch(MOJOS_PER_XCH), "1 XCH");
        assert_eq!(xch(0), "0 XCH");
        assert_eq!(xch(1), "0.000000000001 XCH");
        assert_eq!(xch(MOJOS_PER_XCH + 5_000_000), "1.000005 XCH");
    }

    /// **The rendered STRING is pinned, not the arithmetic** (dig_ecosystem#2957).
    ///
    /// Equality between the two renderers is not enough on its own: the send dialog's `50000000 XCH`
    /// defect survived precisely because its test asserted the same wrong string the code produced.
    /// These are literals a person could read aloud, including the exact figure that went wrong.
    #[test]
    fn the_xch_renderer_produces_the_literal_strings_a_person_reads() {
        assert_eq!(xch(0), "0 XCH");
        assert_eq!(xch(1), "0.000000000001 XCH");
        assert_eq!(xch(1_000_000_000_000), "1 XCH");
        assert_eq!(xch(1_000_005_000_000), "1.000005 XCH");
        // The send dialog once read this out as `50000000 XCH` — a divisor short by twelve places.
        assert_eq!(xch(50_000_000), "0.00005 XCH");
        assert_eq!(xch(u64::MAX), "18446744.073709551615 XCH");
    }

    /// **There is one conversion, and this proves it byte for byte.**
    ///
    /// `xch` delegates to [`crate::amount::format_units`], so the claim that this crate holds a single
    /// mojos-to-XCH rendering is true by construction. This checks the boundaries where a hand-written
    /// second copy would most plausibly diverge: the carry either side of a whole XCH, the smallest
    /// representable amount, and the top of the `u64` range.
    #[test]
    fn the_xch_renderer_is_byte_identical_to_the_crates_one_conversion() {
        for mojos in [
            0,
            1,
            MOJOS_PER_XCH - 1,
            MOJOS_PER_XCH,
            MOJOS_PER_XCH + 1,
            u64::MAX,
        ] {
            assert_eq!(
                xch(mojos),
                format!(
                    "{} XCH",
                    crate::amount::format_units(u128::from(mojos), crate::amount::XCH_DECIMALS)
                ),
                "{mojos} mojos rendered differently by the two spellings"
            );
        }
    }

    /// The transport-less publisher refuses rather than reporting a phantom success.
    #[test]
    fn the_absent_publisher_cannot_report_a_push() {
        assert!(NoPublisher
            .push(&SpendBundle::new(Vec::new(), Default::default()))
            .is_err());
    }

    /// A chain source AND a publisher over one in-process Chia consensus validator.
    ///
    /// Pushed bundles wait in `mempool` until [`farm`](Self::farm) applies them, because the
    /// simulator would otherwise include a transaction the instant it is handed one — and the
    /// pushed-but-not-yet-confirmed state, which is the entire point of the evidence rule, would
    /// then not exist to be observed.
    struct SimulatorChain {
        sim: RefCell<Simulator>,
        mempool: RefCell<Vec<SpendBundle>>,
        /// Every push ever made, counted where the NETWORK sees it. A count taken from the mempool
        /// alone would be reset by farming and could not prove a second spend did not happen.
        pushed: std::cell::Cell<usize>,
    }

    impl SimulatorChain {
        fn new() -> Self {
            let chain = Self {
                sim: RefCell::new(Simulator::new()),
                mempool: RefCell::new(Vec::new()),
                pushed: std::cell::Cell::new(0),
            };
            // Leave genesis behind: no real coin is created in block 0, and a confirmation there is
            // indistinguishable from a fabricated height (dig-account rejects one).
            chain.bury(1);
            chain
        }

        /// Give `puzzle_hash` a confirmed coin of `amount` mojos.
        fn fund(&self, puzzle_hash: Bytes32, amount: u64) {
            self.sim.borrow_mut().new_coin(puzzle_hash, amount);
        }

        /// Include every pushed bundle in a block, then build far enough on top that the result is
        /// buried past `MIN_CONFIRMATION_DEPTH`. A farm that stopped at inclusion would leave the
        /// confirmation shallow, and dig-account would rightly refuse it as evidence.
        fn farm(&self) {
            for bundle in self.mempool.borrow_mut().drain(..) {
                self.sim
                    .borrow_mut()
                    .new_transaction(bundle)
                    .expect("the mint bundle must pass consensus validation");
            }
            self.bury(MIN_CONFIRMATION_DEPTH);
        }

        /// How many bundles have been pushed to this chain, ever — including those already farmed.
        fn pushed(&self) -> usize {
            self.pushed.get()
        }

        fn bury(&self, blocks: u32) {
            for _ in 0..blocks {
                self.sim.borrow_mut().create_block();
            }
        }
    }

    impl ChainSource for SimulatorChain {
        type Error = String;

        fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            Ok(self
                .sim
                .borrow()
                .coin_state(coin_id)
                .map(CoinRecord::from_coin_state))
        }

        fn coin_records_by_puzzle_hash(
            &self,
            puzzle_hash: Bytes32,
            include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            let sim = self.sim.borrow();
            Ok(sim
                .unspent_coins(puzzle_hash, false)
                .into_iter()
                .filter_map(|coin| sim.coin_state(coin.coin_id()))
                .filter(|state| include_spent || state.spent_height.is_none())
                .map(CoinRecord::from_coin_state)
                .collect())
        }

        fn coin_records_by_parent(&self, parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(self
                .sim
                .borrow()
                .children(parent)
                .into_iter()
                .map(CoinRecord::from_coin_state)
                .collect())
        }

        fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
            Ok(self.sim.borrow().coin_spend(coin_id))
        }

        fn resolve_singleton_lineage(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<SingletonLineage>, Self::Error> {
            // An honest refusal: the mint never walks a lineage, so this double does not pretend to.
            Err("lineage resolution is not supported by the simulator double".to_owned())
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            Ok(Some(self.sim.borrow().height()))
        }

        fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
            Ok(None)
        }
    }

    impl SpendPublisher for SimulatorChain {
        fn push(&self, bundle: &SpendBundle) -> Result<PushOutcome, ChainUnavailable> {
            self.pushed.set(self.pushed.get() + 1);
            self.mempool.borrow_mut().push(bundle.clone());
            Ok(PushOutcome::Accepted)
        }
    }
}
