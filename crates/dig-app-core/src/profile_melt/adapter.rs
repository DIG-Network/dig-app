//! The one file that turns [`ProfileMeltSeam`] into a real deletion on dig-account.
//!
//! # Why the whole crate seam is one file
//!
//! [`super`]'s ceremony is written against [`ProfileMeltSeam`]'s two plain owned values, so it holds
//! no chia type, needs no node and spends nothing in a test. That is only worth something if there
//! is exactly ONE place the real types enter, and this is it — the same arrangement
//! [`AccountEditSeam`](crate::profile_edit::AccountEditSeam) has, for the same reason.
//!
//! # §908 — the node signs nothing
//!
//! `ProfileMelter::melt_profile` builds, gates and signs both melt spends in THIS process from the
//! unlocked account's own seed, and hands the publisher an already-signed bundle. Nothing in this
//! file takes a key, a seed or a phrase, and the two seams it reaches the node through
//! ([`ChainSource`] reads, [`SpendPublisher`] pushes) have nowhere to put one.
//!
//! # NC-14 — the sentence a person consents to is the spend that gets signed
//!
//! The consent surface is [`copy::confirm_body`](super::copy::confirm_body), which names the
//! profile, its `did:chia:` identifier, its store, and the fact that both mojos are spent. The
//! authority for those facts is [`ProfileAnchor`] — the same anchor handed to `melt_profile`, which
//! re-reads both singletons and refuses unless the two coins it is about to spend ARE the tips that
//! anchor resolved. Nothing here computes a second description of the destruction beside the one
//! that gets signed.
//!
//! # The one shape mismatch, stated plainly because it decides how [`AccountMeltSeam::melt`] reads
//!
//! The ceremony above was written when deleting a profile was expected to be TWO independent
//! spends, so it asks for one [`MeltHalf`] at a time and is arranged around the half-deleted state
//! that ordering produces. dig-account 0.20 does not produce that state: `melt_profile` puts BOTH
//! melts in ONE bundle, gated to exactly two spends whose coin ids must equal the two tips it
//! resolved. Either both land or neither does.
//!
//! So this seam maps the two halves onto the one bundle rather than pretending to two: the DID half
//! pushes it, and the store half — whose coin that same bundle already spent — reports itself
//! [`ProfileMeltError::AlreadyGone`]. That is not a convenient fiction.
//! [`AccountMeltSeam::confirmation`] asks `melt_status`, which requires BOTH coins to be spent on
//! chain before it answers confirmed, so the half the ceremony never watches separately is
//! nonetheless proved before anything is reported deleted.

use std::sync::{Arc, Mutex};

use chia_protocol::Bytes32;
use dig_account::melt::{MeltError, MeltStatus};
use dig_account::mint::SpendPublisher;
use dig_account::registry::ProfileAnchor;
use dig_account::ProfileIx;
use dig_chainsource_interface::ChainSource;

use super::{MeltHalf, MeltProof, ProfileMeltError, ProfileMeltSeam, PushedMelt};
use crate::account::residency::AccountResidency;

/// The signing domain a deletion is committed under, re-exported so the shell can name mainnet
/// without taking a direct dig-account dependency for one constructor.
pub use dig_account::mint::MintNetwork;

/// The two coin ids one melt bundle spent, remembered so the store half and every confirmation read
/// speak about the SAME bundle the DID half pushed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SpentPair {
    /// The DID singleton's tip, as the bundle spent it.
    did: Bytes32,
    /// The store singleton's tip, as the same bundle spent it.
    store: Bytes32,
}

/// The live seam: dig-account's melter, over this app's node.
///
/// Generic over its chain and publisher so a test can drive it against doubles with no node and no
/// money — the concrete pair the binary builds is
/// [`ControlChainSource`](crate::chain::ControlChainSource) and
/// [`ControlSpendPublisher`](crate::chain::ControlSpendPublisher).
///
/// Bound to ONE profile, decided when it is built. A deletion is irreversible, so the profile it
/// destroys is fixed at construction and can never be re-aimed by an argument.
pub struct AccountMeltSeam<C, P> {
    /// The unlock the melter is derived from, per call, so a lock stops deletions at the next one.
    residency: Arc<AccountResidency>,
    /// Which profile is deleted, and which key signs for it.
    ix: ProfileIx,
    /// The DID and store this profile is anchored to — and the authority the consent surface's
    /// sentence is written from.
    anchor: ProfileAnchor,
    /// Chain reads.
    chain: Arc<C>,
    /// The push, which takes an already-signed bundle (§908).
    publisher: Arc<P>,
    /// The signing domain. `MintNetwork::mainnet()` in the shipped binary.
    network: MintNetwork,
    /// The bundle this seam has already pushed, if any.
    ///
    /// # A double-spend guard, not a cache
    ///
    /// The ceremony asks for two halves and one bundle answers both, so the second ask must NOT
    /// build and sign a second deletion. It could not succeed — the tips it gated against are spent
    /// — but it would pay a fee attempting it, on the one act in this app that cannot be undone.
    pushed: Mutex<Option<SpentPair>>,
}

impl<C, P> AccountMeltSeam<C, P>
where
    C: ChainSource + Send + Sync,
    P: SpendPublisher + Send + Sync,
{
    /// Assemble the seam that deletes the profile at `ix`, anchored at `anchor`.
    pub fn new(
        residency: Arc<AccountResidency>,
        ix: ProfileIx,
        anchor: ProfileAnchor,
        chain: Arc<C>,
        publisher: Arc<P>,
        network: MintNetwork,
    ) -> Self {
        Self {
            residency,
            ix,
            anchor,
            chain,
            publisher,
            network,
            pushed: Mutex::new(None),
        }
    }

    /// The bundle already pushed by this seam, if there is one.
    fn spent_pair(&self) -> Option<SpentPair> {
        self.pushed.lock().ok().and_then(|held| *held)
    }

    /// Build, gate, sign and push the ONE bundle that melts both singletons.
    fn push_the_deletion(&self) -> Result<SpentPair, ProfileMeltError> {
        // Derived per call, never cached: a deletion spends real XCH and destroys a profile
        // permanently, so a melter kept across a lock-now or an idle timeout would go on being able
        // to end profiles after the person locked. The rule `profile_editor` is written to, applied
        // where it matters most.
        let melter = self
            .residency
            .profile_melter()
            .ok_or(ProfileMeltError::Locked)?;

        match melter
            .melt_profile(
                self.ix,
                &self.anchor,
                &*self.chain,
                &*self.publisher,
                &self.network,
            )
            .map_err(|error| self.melt_error(error, MeltHalf::Did))?
        {
            MeltStatus::Pushed {
                did_coin_id,
                store_coin_id,
            } => {
                let pair = SpentPair {
                    did: did_coin_id,
                    store: store_coin_id,
                };
                if let Ok(mut held) = self.pushed.lock() {
                    *held = Some(pair);
                }
                Ok(pair)
            }
            // `melt_profile` pushes and reports what a mempool accepted; it has no way to observe a
            // block, so it never answers confirmed. Treated as unproved rather than as a deletion,
            // which is the direction that under-claims.
            MeltStatus::Confirmed { .. } => Err(ProfileMeltError::ChainUnreachable(
                "the push reported a confirmation it cannot have observed".to_string(),
            )),
        }
    }

    /// Whether the store singleton still has a live coin on chain.
    ///
    /// Asked in exactly one place: when the crate refuses because the DID's lineage has ENDED. That
    /// refusal is ambiguous on its own — a fully deleted profile and a profile whose DID was melted
    /// while its store lived produce the identical error — and the two must not be told to a person
    /// the same way. One says nothing is left; the other says content is still anchored on chain.
    fn store_is_still_live(&self) -> bool {
        self.chain
            .resolve_singleton_lineage(self.anchor.store_launcher_id())
            .ok()
            .flatten()
            .is_some()
    }

    /// Tell this computer's profile registry that the profile ended at `at_height`.
    ///
    /// # Why this lives beside the confirmation and not after the ceremony
    ///
    /// Reached from the one place that has CHAIN PROOF both coins are spent. A registry that still
    /// lists a profile whose singletons are gone is the app contradicting the chain, and the window
    /// in which it does so should be the poll that proved the melt — not a later step some caller has
    /// to remember.
    ///
    /// `record_melted` moves the active slot when the deleted profile was the active one, so this is
    /// also what makes deleting the profile a person is currently using leave the wallet somewhere
    /// real.
    ///
    /// # Why a failure here does not fail the deletion
    ///
    /// The coins are spent. Reporting the deletion as failed because a JSON file could not be
    /// written would tell a person their profile survived when it did not, which is the more
    /// dangerous of the two wrong answers. It is logged, and the next confirmed read records it
    /// again — `record_melted` is idempotent.
    fn record_the_ending(&self, at_height: u32) {
        if let Err(why) = self.residency.profiles().record_melted(self.ix, at_height) {
            tracing::warn!(
                ix = self.ix.0,
                %why,
                "the profile was deleted on chain, but this computer could not write it \
                 down; it will be recorded again on the next confirmed read"
            );
        }
    }

    /// The crate's failure, in the ceremony's vocabulary.
    ///
    /// `half` is which half was being asked for, because [`MeltError::NoDid`] means opposite things
    /// to the two: to the DID half it is *this lineage already ended*, and to the store half — which
    /// is only ever reached when no bundle was pushed — it is *the deletion could not run at all*,
    /// where the store may still be live.
    fn melt_error(&self, error: MeltError, half: MeltHalf) -> ProfileMeltError {
        match error {
            MeltError::Locked => ProfileMeltError::Locked,
            // Opposite remedies, and they must never merge: a rejected bundle left both singletons
            // alive and is rebuilt, an unanswered chain may have a deletion in flight and is WAITED
            // on. Collapsing them tells a person to delete again while their first bundle sits in a
            // mempool.
            MeltError::Rejected(why) => ProfileMeltError::Rejected(why),
            MeltError::ChainUnreachable(why) => ProfileMeltError::ChainUnreachable(why),
            MeltError::Refused(why) | MeltError::Build(why) => ProfileMeltError::Refused(why),
            MeltError::Format(why) => ProfileMeltError::Unreadable(why),
            // The DID's lineage has ended. Whether that means the PROFILE is gone depends on the
            // other singleton, and only a chain read can say which.
            MeltError::NoDid => {
                if half == MeltHalf::Did || !self.store_is_still_live() {
                    ProfileMeltError::AlreadyGone
                } else {
                    ProfileMeltError::Refused(
                        "this profile's identity was already deleted, but its content store is \
                         still on the blockchain. DIG cannot delete a store on its own."
                            .to_string(),
                    )
                }
            }
            // The store's lineage has ended while the DID's has not, so there is no two-singleton
            // deletion to build. Never reported as the profile being gone: its identity still
            // resolves.
            MeltError::NoStore => ProfileMeltError::Refused(
                "this profile's content store is no longer on the blockchain, so DIG cannot delete \
                 the profile as a whole."
                    .to_string(),
            ),
        }
    }
}

impl<C, P> ProfileMeltSeam for AccountMeltSeam<C, P>
where
    C: ChainSource + Send + Sync,
    P: SpendPublisher + Send + Sync,
{
    /// Push the deletion on the DID half; report the store half as already spent by that same push.
    ///
    /// See this module's header for why one bundle answers two asks. The ordering the ceremony
    /// guarantees — DID first, always — is what makes the store arm reachable only AFTER the bundle
    /// exists.
    fn melt(&self, half: MeltHalf) -> Result<PushedMelt, ProfileMeltError> {
        if let Some(pair) = self.spent_pair() {
            return match half {
                // Idempotent rather than a second signature: the bundle is already in a mempool.
                MeltHalf::Did => Ok(PushedMelt {
                    half,
                    coin_id: hex::encode(pair.did),
                }),
                MeltHalf::Store => Err(ProfileMeltError::AlreadyGone),
            };
        }
        let pair = self.push_the_deletion()?;
        Ok(PushedMelt {
            half,
            coin_id: hex::encode(match half {
                MeltHalf::Did => pair.did,
                MeltHalf::Store => pair.store,
            }),
        })
    }

    /// Whether the chain now shows BOTH of this deletion's coins spent.
    ///
    /// `coin_id` is the DID coin the ceremony is watching, and it is CHECKED against the bundle this
    /// seam pushed rather than trusted: a confirmation read that answered for some other coin would
    /// report a profile deleted on the strength of an unrelated spend.
    ///
    /// Both coins, never one, because a profile ends when its DID AND its store are gone —
    /// `melt_status` holds that rule and this does not restate it.
    fn confirmation(&self, coin_id: &str) -> Result<Option<MeltProof>, ProfileMeltError> {
        let Some(pair) = self.spent_pair() else {
            return Err(ProfileMeltError::ChainUnreachable(
                "DIG has not pushed a deletion for this profile, so there is nothing to confirm"
                    .to_string(),
            ));
        };
        if coin_id != hex::encode(pair.did) {
            return Err(ProfileMeltError::ChainUnreachable(format!(
                "DIG was asked to confirm a coin it did not spend deleting this profile: {coin_id}"
            )));
        }
        let melter = self
            .residency
            .profile_melter()
            .ok_or(ProfileMeltError::Locked)?;

        match melter
            .melt_status(pair.did, pair.store, &*self.chain)
            .map_err(|error| self.melt_error(error, MeltHalf::Did))?
        {
            MeltStatus::Confirmed { at_height } => {
                self.record_the_ending(at_height);
                Ok(Some(MeltProof { height: at_height }))
            }
            // A real answer from the chain: at least one coin is not spent yet. Distinct from the
            // `Err` above, which is nobody having been able to ask.
            MeltStatus::Pushed { .. } => Ok(None),
        }
    }
}
