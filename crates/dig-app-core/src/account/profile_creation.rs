//! The driver that turns a funded wallet into a recorded profile (dig_ecosystem#2989).
//!
//! [`profile_mint`](crate::account::profile_mint) is the DOOR — three calls that push, watch and
//! record. This module is the thing that WALKS through it: it begins the ceremony, polls it until
//! the chain has proven both halves, records the profile, and reports every step on the way so a
//! surface can draw progress.
//!
//! # The one property everything here is arranged around
//!
//! **A profile is recorded only from confirmed on-chain evidence.** dig-account enforces that by
//! giving `MintedDid` and `ConfirmedStore` no public producer at all: the only place a host obtains
//! either is [`ProfileMintStatus::Confirmed`], reached only from a chain read of a coin buried under
//! the confirmation depth. This module keeps the property rather than merely respecting it — see
//! [`Ceremony::Evidence`], which is why `record` cannot be called from any other arm.
//!
//! # Money is reported with an UNKNOWN arm, never rounded to a certainty
//!
//! Every stopped creation carries a [`Spent`] verdict, and its middle arm is the load-bearing one: a
//! chain that could not be reached says NOTHING about whether a bundle was included. Telling
//! somebody their funds are untouched when a mint may be in a mempool is what invites a second paid
//! mint; telling them money is gone when it is not is a claim about their money no read supports.
//! The same three-way honesty the send path already draws with
//! [`SendProgress`](crate::wallet::sending::SendProgress).

use chia_protocol::Bytes32;
use dig_account::mint::{MintError, ProfileMintStatus, ProfileSeed};
use dig_account::ProfileIx;

use crate::account::profile_mint::ProfileMintDoor;
use crate::account::profile_session::MintDoorError;

/// The profile's content, re-exported so the one binary that builds a seed reaches it beside the
/// driver that consumes it rather than through a second dependency path.
pub use dig_account::mint::ProfileSeed as Seed;

/// A profile ceremony the driver can drive.
///
/// # Why this exists beside [`ProfileMintDoor`], which is already a trait
///
/// The door's statuses carry dig-account's mint evidence, which has **no public producer** — so no
/// test double can return a confirmed one, and the driver's most important behaviour would be
/// untestable. This trait keeps the same shape with the evidence as an ASSOCIATED TYPE, so a double
/// substitutes its own (`()`), while the property that matters survives intact:
/// [`record`](Self::record) consumes an `Evidence`, and an `Evidence` exists only inside
/// [`Reached::Confirmed`]. A driver that recorded without a confirmation would not compile.
///
/// Every real door reaches this through the blanket implementation below, so there is exactly one
/// mapping from dig-account's statuses to [`Reached`].
pub trait Ceremony {
    /// Proof that BOTH halves confirmed on chain.
    ///
    /// For a real door this is dig-account's `(MintedDid, ConfirmedStore)`, which nothing outside
    /// dig-account can construct.
    type Evidence;

    /// Reserve the index and push the DID half. **On mainnet this spends real XCH.**
    fn begin(&self, seed: &ProfileSeed) -> Result<Reached<Self::Evidence>, MintDoorError>;

    /// Drive the ceremony forward from what the chain now says. Pushes only on evidence.
    fn advance(&self) -> Result<Reached<Self::Evidence>, MintDoorError>;

    /// Record the confirmed profile, returning the index it took.
    fn record(
        &self,
        evidence: Self::Evidence,
        label: Option<String>,
    ) -> Result<ProfileIx, MintDoorError>;
}

impl<D: ProfileMintDoor + ?Sized> Ceremony for D {
    type Evidence = (dig_account::mint::MintedDid, dig_account::mint::ConfirmedStore);

    fn begin(&self, seed: &ProfileSeed) -> Result<Reached<Self::Evidence>, MintDoorError> {
        ProfileMintDoor::begin(self, seed).map(Reached::of_status)
    }

    fn advance(&self) -> Result<Reached<Self::Evidence>, MintDoorError> {
        ProfileMintDoor::advance(self).map(Reached::of_status)
    }

    fn record(
        &self,
        (did, store): Self::Evidence,
        label: Option<String>,
    ) -> Result<ProfileIx, MintDoorError> {
        ProfileMintDoor::record(self, &did, &store, label)
    }
}

/// What one ceremony call answered.
///
/// Two arms rather than four, because the driver makes exactly one decision from a status: *is this
/// finished?* The four-way detail a person is SHOWN lives in [`CreationStep`], which both arms carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reached<E> {
    /// Not finished. Carries what to show for it.
    Underway(CreationStep),
    /// Both halves are confirmed on chain, with the proof.
    Confirmed {
        /// The unforgeable evidence, which [`Ceremony::record`] consumes.
        evidence: E,
        /// The same facts as plain values, for a surface to draw.
        profile: ConfirmedProfile,
    },
}

impl Reached<(dig_account::mint::MintedDid, dig_account::mint::ConfirmedStore)> {
    /// The ONE mapping from dig-account's ladder to the driver's vocabulary.
    ///
    /// [`ProfileMintStatus`] is `#[non_exhaustive]`, so a stage this build has never heard of is
    /// possible. It maps to [`CreationStep::Unrecognised`], which is neither finished nor nothing —
    /// an unknown stage must never be read as *done* (it would record nothing and claim success) nor
    /// as *nothing happened* (money may be spent).
    fn of_status(status: ProfileMintStatus) -> Self {
        match status {
            ProfileMintStatus::DidPending { did_coin_id } => {
                Self::Underway(CreationStep::DidSubmitted {
                    did_coin_id: id(did_coin_id),
                })
            }
            ProfileMintStatus::DidConfirmedStoreNotLaunched(did) => {
                Self::Underway(CreationStep::DidConfirmed {
                    did: did.did().to_owned(),
                    did_coin_id: id(did.coin_id()),
                    confirmed_height: did.confirmed_height(),
                })
            }
            ProfileMintStatus::StorePending {
                did,
                store_launcher_id,
            } => Self::Underway(CreationStep::StoreSubmitted {
                did: did.did().to_owned(),
                store_launcher_id: id(store_launcher_id),
            }),
            ProfileMintStatus::Confirmed { did, store } => Self::Confirmed {
                profile: ConfirmedProfile {
                    did: did.did().to_owned(),
                    did_coin_id: id(did.coin_id()),
                    did_confirmed_height: did.confirmed_height(),
                    store_launcher_id: id(store.launcher_id()),
                    store_confirmed_height: store.confirmed_height(),
                },
                evidence: (did, store),
            },
            _ => Self::Underway(CreationStep::Unrecognised),
        }
    }
}

/// A chain id in the `0x…` form every DIG surface prints.
fn id(bytes: Bytes32) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// How far a creation has been PROVEN to reach. Each arm names evidence, never an intention.
///
/// The DID arms say *submitted* rather than *created* deliberately: a push is one node's acceptance,
/// and the whole reason the ceremony has four stages is that acceptance is not confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreationStep {
    /// The DID bundle has been pushed and **nothing is proven**.
    DidSubmitted {
        /// The coin whose confirmation will be the DID's evidence.
        did_coin_id: String,
    },
    /// The DID exists on chain and the store has not been launched.
    ///
    /// dig-account calls this *the state that costs money to get wrong*: funds are committed, an
    /// identity exists, and there is no profile. Resuming means launching the store — **never**
    /// re-minting the DID.
    DidConfirmed {
        /// The identity that now exists.
        did: String,
        /// Its coin.
        did_coin_id: String,
        /// The height it confirmed at.
        confirmed_height: u32,
    },
    /// The store bundle has been broadcast against a confirmed DID.
    StoreSubmitted {
        /// The identity that already exists.
        did: String,
        /// The store singleton's launcher id, once it confirms.
        store_launcher_id: String,
    },
    /// Both halves are confirmed on chain.
    Confirmed(ConfirmedProfile),
    /// A stage this build does not recognise, because dig-account's ladder is `#[non_exhaustive]`.
    ///
    /// Not *finished* and not *nothing happened*: an unrecognised stage is a measurement this build
    /// cannot read, and both certainties would be invented.
    Unrecognised,
}

impl CreationStep {
    /// Whether reaching this step means money has certainly left the wallet.
    ///
    /// True from [`DidConfirmed`](Self::DidConfirmed) onwards: the DID coin is on chain, so its
    /// funding coin was spent. [`DidSubmitted`](Self::DidSubmitted) is deliberately NOT certain — a
    /// push is an acceptance, not an inclusion — and [`Unrecognised`](Self::Unrecognised) cannot be
    /// judged at all.
    fn money_certainly_moved(&self) -> bool {
        matches!(
            self,
            Self::DidConfirmed { .. } | Self::StoreSubmitted { .. } | Self::Confirmed(_)
        )
    }
}

/// A profile the chain has confirmed, as plain values.
///
/// # Why the copy takes THIS and not dig-account's evidence
///
/// The evidence types have no public producer, by design, so the screenshot gallery could not build
/// one to photograph — and faking one would mean adding the constructor whose absence is the entire
/// unforgeability property. Rendering from plain values keeps the property and lets the gallery pass
/// literals while the real caller passes accessor results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedProfile {
    /// The DID that was minted.
    pub did: String,
    /// Its coin id.
    pub did_coin_id: String,
    /// The height the DID confirmed at.
    pub did_confirmed_height: u32,
    /// The store singleton launched from that DID's coin.
    pub store_launcher_id: String,
    /// The height the store confirmed at.
    pub store_confirmed_height: u32,
}

/// Whether a stopped creation moved the user's money.
///
/// # The middle arm is the whole point
///
/// Two of the three states are certainties a read can support. The third is what an unreachable
/// chain actually leaves behind, and folding it into either certainty is the app lying about money:
/// collapsing it to [`Nothing`](Self::Nothing) invites a second paid mint, and collapsing it to
/// [`Committed`](Self::Committed) tells somebody their funds are gone on no evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spent {
    /// Nothing left the wallet. Only stated where the failure happened BEFORE a push, or where the
    /// network itself answered no.
    Nothing,
    /// It cannot be known. A bundle may be in a mempool right now.
    Unknown {
        /// What went wrong, in the deciding party's own words.
        detail: String,
    },
    /// Money has certainly moved: a coin this ceremony paid for is on chain.
    Committed,
}

impl Spent {
    /// What a [`MintError`] alone says about the money, before any stage is considered.
    ///
    /// Read off dig-account's own taxonomy, which states the fact for each variant:
    ///
    /// * `InsufficientFunds`, `Locked`, `FeeAboveCeiling`, `Build`, `Journal`, `Refused` — every one
    ///   of these is decided BEFORE a bundle is built or pushed, so nothing left the wallet.
    /// * `Rejected` — *"the mempool declined it. The user's funds did not move"*.
    /// * `ChainUnreachable` — *"the outcome is UNKNOWN, never no"*.
    ///
    /// # The wildcard falls to `Unknown`, and that direction is not arbitrary
    ///
    /// [`MintError`] is `#[non_exhaustive]`. A future variant reaching a default of
    /// [`Nothing`](Self::Nothing) would be this app promising untouched funds about a failure it has
    /// never heard of — precisely the lie this type exists to prevent. `Unknown` is the arm that
    /// claims the least.
    fn of_error(error: &MintError) -> Self {
        match error {
            MintError::InsufficientFunds { .. }
            | MintError::Locked
            | MintError::FeeAboveCeiling { .. }
            | MintError::Build(_)
            | MintError::Journal(_)
            | MintError::Refused(_)
            | MintError::Rejected(_) => Self::Nothing,
            MintError::ChainUnreachable(why) => Self::Unknown {
                detail: why.clone(),
            },
            other => Self::Unknown {
                detail: other.to_string(),
            },
        }
    }

    /// The verdict for a creation that stopped at `reached` with `fault`.
    ///
    /// The STAGE outranks the error: once the DID coin is on chain the money is spent whatever the
    /// next call complained about. Below that, a pushed-but-unproven DID is [`Unknown`](Self::Unknown)
    /// even when the fault itself looks harmless — the push already happened.
    fn of(reached: Option<&CreationStep>, fault: &MintDoorError) -> Self {
        match reached {
            Some(step) if step.money_certainly_moved() => Self::Committed,
            Some(_) => Self::Unknown {
                detail: fault.to_string(),
            },
            None => match &fault.mint {
                Some(error) => Self::of_error(error),
                // The mint SUCCEEDED and only the write did not, so a bundle is in flight.
                None => Self::Unknown {
                    detail: fault.to_string(),
                },
            },
        }
    }
}

/// How the creation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Creation {
    /// The profile is confirmed on chain AND recorded on this machine.
    ///
    /// When it is the account's first, recording also made it active.
    Created {
        /// The index it took.
        ix: ProfileIx,
        /// Its on-chain evidence, as plain values.
        profile: ConfirmedProfile,
    },
    /// The creation did not finish. It is resumable — the journal entry is persisted.
    Stopped(Stopped),
}

/// A creation that did not finish, and everything a person needs in order to decide what to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stopped {
    /// The last step the chain PROVED, or `None` when nothing was ever pushed.
    pub reached: Option<CreationStep>,
    /// What is known about the money.
    pub spent: Spent,
    /// Why it stopped, in the deciding party's own words.
    pub why: String,
    /// Whether this machine may have paid for a mint it will not remember after a restart.
    ///
    /// Straight from [`MintDoorError::may_be_forgotten`]. A surface MUST NOT tell somebody to try
    /// again while this is true.
    pub may_be_forgotten: bool,
}

/// How long the driver watches, and how much transient fault it absorbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watch {
    /// The most [`Ceremony::advance`] calls to make before stopping and reporting.
    pub polls: u32,
    /// How many CONSECUTIVE unknown-outcome faults to absorb before stopping.
    pub tolerated_faults: u32,
}

impl Default for Watch {
    /// A Chia block is roughly 18.75 seconds and two confirmations must be buried, so a caller
    /// ticking every few seconds needs a budget in the hundreds rather than the tens. Six hundred
    /// polls at a five-second tick is about fifty minutes — long enough for a congested mempool,
    /// short enough that a surface is not held forever.
    fn default() -> Self {
        Self {
            polls: 600,
            tolerated_faults: 20,
        }
    }
}

/// Begin a whole-profile creation and drive it until the chain proves it, then record it.
///
/// `tick` is called between polls, so the cadence belongs to the caller: production sleeps, tests
/// return instantly. `report` is called with every step reached, so a surface can draw progress
/// without asking a second time.
///
/// # Money
///
/// The FIRST thing this does is [`Ceremony::begin`], which on mainnet spends real XCH. Everything
/// after it only reads and — once the chain proves both halves — writes the registry.
///
/// # How an `advance` fault is handled, and why
///
/// An unreachable node is the ordinary weather of this loop and it says nothing about the mint, so a
/// fault whose [`Spent`] verdict is [`Unknown`](Spent::Unknown) is ABSORBED, up to
/// [`Watch::tolerated_faults`] in a row, and the counter resets on any answer. Losing a paid-for
/// mint because one poll failed is the expensive error here — the mint is still on chain and still
/// resumable, but the person is watching a window that gave up.
///
/// A fault that is NOT unknown is a decided answer — the registry refused, the account locked — and
/// re-asking cannot change it, so it stops immediately. So does a failed PERSIST at any point: the
/// in-memory registry has moved on and the disk has not, and continuing would write more that will
/// not survive a restart.
///
/// Spinning forever is not among the options: the poll budget bounds the loop, and exhausting it is
/// reported as a stop that says how far it got rather than as a failure.
pub fn create_profile<C>(
    ceremony: &C,
    seed: &ProfileSeed,
    label: Option<String>,
    watch: Watch,
    tick: &mut dyn FnMut(),
    report: &mut dyn FnMut(&CreationStep),
) -> Creation
where
    C: Ceremony + ?Sized,
{
    let mut reached: Option<CreationStep> = None;

    let begun = match ceremony.begin(seed) {
        Ok(begun) => begun,
        Err(fault) => return stop(None, &fault),
    };

    let mut answer = begun;
    let mut consecutive_faults = 0;

    for poll in 0..watch.polls.saturating_add(1) {
        match answer {
            Reached::Confirmed { evidence, profile } => {
                report(&CreationStep::Confirmed(profile.clone()));
                return match ceremony.record(evidence, label) {
                    Ok(ix) => Creation::Created { ix, profile },
                    // The profile EXISTS on chain and this machine could not write it down. Neither
                    // a success nor a failure, and `Spent::Committed` says so.
                    Err(fault) => stop(Some(CreationStep::Confirmed(profile)), &fault),
                };
            }
            Reached::Underway(step) => {
                report(&step);
                reached = Some(step);
            }
        }

        // The budget counts POLLS, and the status above came from `begin` or the previous poll.
        if poll == watch.polls {
            break;
        }

        tick();
        answer = match ceremony.advance() {
            Ok(answer) => {
                consecutive_faults = 0;
                answer
            }
            Err(fault) => {
                let transient = fault.mint.is_some()
                    && matches!(Spent::of(None, &fault), Spent::Unknown { .. })
                    && !fault.may_be_forgotten();
                consecutive_faults += 1;
                if !transient || consecutive_faults > watch.tolerated_faults {
                    return stop(reached, &fault);
                }
                Reached::Underway(reached.clone().unwrap_or(CreationStep::Unrecognised))
            }
        };
    }

    Creation::Stopped(Stopped {
        spent: match reached.as_ref().is_some_and(CreationStep::money_certainly_moved) {
            true => Spent::Committed,
            false => Spent::Unknown {
                detail: "the chain had not confirmed it yet".to_owned(),
            },
        },
        reached,
        why: "DIG stopped watching after the time it allows for a creation".to_owned(),
        may_be_forgotten: false,
    })
}

/// The one construction of a stopped creation, so its money verdict has a single derivation.
fn stop(reached: Option<CreationStep>, fault: &MintDoorError) -> Creation {
    Creation::Stopped(Stopped {
        spent: Spent::of(reached.as_ref(), fault),
        reached,
        why: fault.to_string(),
        may_be_forgotten: fault.may_be_forgotten(),
    })
}

/// The words a creation puts on screen.
///
/// # The rule this copy may never break
///
/// **It may not promise that funds are untouched unless [`Spent::Nothing`] says so.** The funding
/// window's own copy carries that promise honestly, because that window spends nothing; the moment a
/// ceremony has begun the same sentence becomes a claim about money that no read supports.
///
/// Every money figure goes through `chain_mint::xch`, this crate's single mojos-to-XCH conversion —
/// a second copy of that arithmetic is what has twice put a wrong figure on a screen here.
pub mod copy {
    use super::{ConfirmedProfile, CreationStep, Spent, Stopped};

    /// The title over every creation window.
    pub const TITLE: &str = "DIG — Creating your profile";

    /// The heading while a creation is running.
    pub const RUNNING_HEADING: &str = "DIG is creating your profile";

    /// The title over a finished creation.
    pub const CREATED_TITLE: &str = "DIG — Your profile is ready";
    /// Its heading.
    pub const CREATED_HEADING: &str = "Your profile has been created";

    /// The title over a creation that stopped.
    pub const STOPPED_TITLE: &str = "DIG — Profile creation stopped";
    /// Its heading.
    pub const STOPPED_HEADING: &str = "DIG stopped before your profile was finished";

    /// One line describing where a running creation stands.
    ///
    /// Every line names what has been PROVEN. The submitted lines say so in as many words, because
    /// the gap between *pushed* and *on chain* is minutes wide and is where a person is most likely
    /// to assume they are finished.
    pub fn step_line(step: &CreationStep) -> String {
        match step {
            CreationStep::DidSubmitted { did_coin_id } => format!(
                "Your identity has been submitted to the blockchain and is waiting to be \
                 confirmed. Nothing is settled yet.\n\nCoin to watch: {did_coin_id}"
            ),
            CreationStep::DidConfirmed {
                did,
                confirmed_height,
                ..
            } => format!(
                "Your identity is on the blockchain, confirmed at block {confirmed_height}. DIG is \
                 now launching its store, which is the second half of a profile.\n\n{did}"
            ),
            CreationStep::StoreSubmitted {
                did,
                store_launcher_id,
            } => format!(
                "Your identity is on the blockchain and its store has been submitted, waiting to be \
                 confirmed.\n\n{did}\nStore: {store_launcher_id}"
            ),
            CreationStep::Confirmed(profile) => created_body(profile),
            CreationStep::Unrecognised => "DIG reached a stage of the creation that this version \
                 does not recognise. Your creation is still on the blockchain; a newer version of \
                 DIG will be able to read it."
                .to_owned(),
        }
    }

    /// What a finished creation says, with the evidence a person can look up themselves.
    ///
    /// Takes plain values rather than dig-account's evidence types for the reason
    /// [`ConfirmedProfile`] states: those types have no public producer, so the screenshot gallery
    /// could not photograph this window without a constructor whose absence IS the unforgeability
    /// property.
    pub fn created_body(profile: &ConfirmedProfile) -> String {
        let ConfirmedProfile {
            did,
            did_coin_id,
            did_confirmed_height,
            store_launcher_id,
            store_confirmed_height,
        } = profile;
        format!(
            "Your profile is on the blockchain and DIG has recorded it on this computer. It is now \
             your active profile, so publishing and signing use it.\n\n\
             {did}\n\
             Identity coin: {did_coin_id}, confirmed at block {did_confirmed_height}\n\
             Store: {store_launcher_id}, confirmed at block {store_confirmed_height}"
        )
    }

    /// What a stopped creation says: how far it got, what is known about the money, and that it can
    /// be resumed.
    ///
    /// # Resumable, and said so plainly
    ///
    /// The journal entry is persisted before anything is pushed, so a stopped creation is a paused
    /// one. A window implying the money is lost would be wrong AND would invite a second mint, which
    /// is the expensive mistake on this path.
    pub fn stopped_body(stopped: &Stopped) -> String {
        let progress = match &stopped.reached {
            Some(step) => step_line(step),
            None => "Nothing was submitted to the blockchain.".to_owned(),
        };
        let money = match &stopped.spent {
            Spent::Nothing => "No money left your wallet. Your funds are where they were.".to_owned(),
            Spent::Unknown { detail } => format!(
                "DIG cannot tell whether this has cost you anything yet: what it submitted may \
                 still be included by the blockchain. Do NOT start a second creation — check this \
                 one first.\n\n{detail}"
            ),
            Spent::Committed => "This has already cost you: part of your profile is on the \
                 blockchain. Starting again would pay a second time and leave the first half \
                 stranded, so do not."
                .to_owned(),
        };
        let forgotten = match stopped.may_be_forgotten {
            true => "\n\nDIG could not save its record of this creation on this computer, so a \
                     restart will not remember it. Do not start another one.",
            false => "\n\nDIG saved where this got to, so it can carry on from here.",
        };
        format!("{progress}\n\n{money}\n\n{}{forgotten}", stopped.why)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use crate::account::profile_session::PersistOutcome;

    /// A plausible mainnet height, so nothing passes because the numbers are small.
    const HEIGHT: u32 = 5_412_009;
    /// A full-length coin id, since its rendering is part of what the copy tests read.
    const DID_COIN: &str = "0x9f2c41a7e5b8d03c6a1f7e94b2d8c05e3a7f61b9d4c28e07a5f3b1c9d6e024f80";

    fn confirmed_profile() -> ConfirmedProfile {
        ConfirmedProfile {
            did: "did:chia:1exampleprofile".to_owned(),
            did_coin_id: DID_COIN.to_owned(),
            did_confirmed_height: HEIGHT,
            store_launcher_id: "0xstore".to_owned(),
            store_confirmed_height: HEIGHT + 4,
        }
    }

    fn submitted() -> CreationStep {
        CreationStep::DidSubmitted {
            did_coin_id: DID_COIN.to_owned(),
        }
    }

    fn did_confirmed() -> CreationStep {
        CreationStep::DidConfirmed {
            did: "did:chia:1exampleprofile".to_owned(),
            did_coin_id: DID_COIN.to_owned(),
            confirmed_height: HEIGHT,
        }
    }

    fn fault(mint: MintError) -> MintDoorError {
        MintDoorError {
            mint: Some(mint),
            persisted: PersistOutcome::Written,
        }
    }

    /// A ceremony scripted answer by answer.
    ///
    /// Its `Evidence` is `()`, which is what lets a test reach the confirmed arm at all — dig-account's
    /// real evidence has no public producer. The counters are what the assertions read: a driver
    /// that recorded from the wrong arm shows up as `records` moving without a confirmation.
    struct ScriptedCeremony {
        /// What `begin` answers.
        begins: RefCell<Option<Result<Reached<()>, MintDoorError>>>,
        /// What successive `advance` calls answer, front first. Exhaustion repeats the last answer,
        /// so an endless-`DidPending` door is expressible without a million-entry script.
        advances: RefCell<Vec<Result<Reached<()>, MintDoorError>>>,
        /// The answer an exhausted script keeps giving.
        forever: RefCell<Option<Reached<()>>>,
        /// How many times anything asked this to record.
        records: std::cell::Cell<usize>,
        /// How many times `advance` was called.
        advanced: std::cell::Cell<usize>,
        /// What `record` answers.
        record_fails: Option<MintError>,
    }

    impl ScriptedCeremony {
        /// A ceremony that begins with `first` and then answers `then`, repeating its last answer.
        fn new(first: Reached<()>, then: Vec<Reached<()>>) -> Self {
            let forever = then.last().cloned().or(Some(first.clone()));
            Self {
                begins: RefCell::new(Some(Ok(first))),
                advances: RefCell::new(then.into_iter().map(Ok).collect()),
                forever: RefCell::new(forever),
                records: std::cell::Cell::default(),
                advanced: std::cell::Cell::default(),
                record_fails: None,
            }
        }

        /// A ceremony whose `begin` fails outright.
        fn refusing(why: MintError) -> Self {
            Self {
                begins: RefCell::new(Some(Err(fault(why)))),
                advances: RefCell::new(Vec::new()),
                forever: RefCell::new(None),
                records: std::cell::Cell::default(),
                advanced: std::cell::Cell::default(),
                record_fails: None,
            }
        }

        /// The happy ladder: pushed, DID confirmed, store pushed, both confirmed.
        fn walks_the_ladder() -> Self {
            Self::new(
                Reached::Underway(submitted()),
                vec![
                    Reached::Underway(did_confirmed()),
                    Reached::Underway(CreationStep::StoreSubmitted {
                        did: "did:chia:1exampleprofile".to_owned(),
                        store_launcher_id: "0xstore".to_owned(),
                    }),
                    Reached::Confirmed {
                        evidence: (),
                        profile: confirmed_profile(),
                    },
                ],
            )
        }

        /// The same ladder with `n` unreachable-chain faults spliced in before each real answer.
        fn with_faults_before_each_answer(n: usize) -> Self {
            let mut script: Vec<Result<Reached<()>, MintDoorError>> = Vec::new();
            for answer in [
                Reached::Underway(did_confirmed()),
                Reached::Confirmed {
                    evidence: (),
                    profile: confirmed_profile(),
                },
            ] {
                for _ in 0..n {
                    script.push(Err(fault(MintError::ChainUnreachable("no route".into()))));
                }
                script.push(Ok(answer));
            }
            Self {
                begins: RefCell::new(Some(Ok(Reached::Underway(submitted())))),
                advances: RefCell::new(script),
                forever: RefCell::new(None),
                records: std::cell::Cell::default(),
                advanced: std::cell::Cell::default(),
                record_fails: None,
            }
        }
    }

    impl Ceremony for ScriptedCeremony {
        type Evidence = ();

        fn begin(&self, _seed: &ProfileSeed) -> Result<Reached<()>, MintDoorError> {
            self.begins
                .borrow_mut()
                .take()
                .expect("begin is called exactly once")
        }

        fn advance(&self) -> Result<Reached<()>, MintDoorError> {
            self.advanced.set(self.advanced.get() + 1);
            let mut queued = self.advances.borrow_mut();
            match queued.is_empty() {
                false => queued.remove(0),
                true => Ok(self
                    .forever
                    .borrow()
                    .clone()
                    .expect("an exhausted script has a repeating answer")),
            }
        }

        fn record(&self, (): (), _label: Option<String>) -> Result<ProfileIx, MintDoorError> {
            self.records.set(self.records.get() + 1);
            match &self.record_fails {
                None => Ok(ProfileIx::ROOT),
                Some(why) => Err(MintDoorError {
                    mint: Some(MintError::Journal(why.to_string())),
                    persisted: PersistOutcome::Written,
                }),
            }
        }
    }

    /// Drive `ceremony` with an instant tick, returning the outcome and every step reported.
    fn drive(ceremony: &ScriptedCeremony, watch: Watch) -> (Creation, Vec<CreationStep>) {
        let mut steps = Vec::new();
        let outcome = create_profile(
            ceremony,
            &ProfileSeed::new(),
            Some("home".to_owned()),
            watch,
            &mut || {},
            &mut |step| steps.push(step.clone()),
        );
        (outcome, steps)
    }

    /// **The whole ladder walked end to end records the profile, exactly once.**
    ///
    /// The control every refusal test below needs: without it, a driver that recorded nothing ever
    /// would pass all of them.
    #[test]
    fn a_confirmed_ceremony_is_recorded() {
        let ceremony = ScriptedCeremony::walks_the_ladder();

        let (outcome, steps) = drive(&ceremony, Watch::default());

        assert_eq!(
            outcome,
            Creation::Created {
                ix: ProfileIx::ROOT,
                profile: confirmed_profile(),
            }
        );
        assert_eq!(ceremony.records.get(), 1, "a profile is recorded once");
        assert_eq!(
            steps,
            vec![
                submitted(),
                did_confirmed(),
                CreationStep::StoreSubmitted {
                    did: "did:chia:1exampleprofile".to_owned(),
                    store_launcher_id: "0xstore".to_owned(),
                },
                CreationStep::Confirmed(confirmed_profile()),
            ],
            "every step a person is shown must be reported, in order"
        );
    }

    /// **A ceremony that only ever answers `DidPending` NEVER records a profile, however many ticks
    /// elapse.**
    ///
    /// Makes impossible: a profile recorded from a push receipt. A push is one node's acceptance and
    /// proves nothing, so a driver that treated elapsed time — or a big enough poll count — as
    /// evidence would write an identity into the registry that may not exist on chain.
    ///
    /// # Why the fixture polls a large number of times rather than a few
    ///
    /// The nearest wrong implementation is not one that records immediately; it is one that gives up
    /// waiting and records what it has. Three ticks could not tell the two apart. This exhausts the
    /// entire budget, so the ONLY way to pass is to never record without a confirmation — and the
    /// control above proves the driver can still record when one arrives.
    #[test]
    fn a_mint_that_never_confirms_is_never_recorded() {
        let ceremony = ScriptedCeremony::new(Reached::Underway(submitted()), Vec::new());
        let watch = Watch {
            polls: 500,
            tolerated_faults: 0,
        };

        let (outcome, steps) = drive(&ceremony, watch);

        assert_eq!(ceremony.records.get(), 0, "a pushed bundle is not a profile");
        assert_eq!(
            ceremony.advanced.get(),
            500,
            "the whole budget must genuinely have been spent, or this proves nothing about waiting"
        );
        let Creation::Stopped(stopped) = outcome else {
            panic!("an unconfirmed mint is not a created profile");
        };
        assert_eq!(stopped.reached, Some(submitted()));
        assert!(
            matches!(stopped.spent, Spent::Unknown { .. }),
            "a submitted-but-unconfirmed bundle may yet be included, so the money is unknown"
        );
        assert!(steps.len() > 1, "progress must be reported while waiting");
    }

    /// **A `begin` that fails before any push reports that nothing was spent, and never advances.**
    ///
    /// The three legs vary only the error, and each is a DIFFERENT sentence a person is owed:
    /// nothing spent, nothing spent, and unknown.
    #[test]
    fn a_refused_beginning_reports_the_money_honestly() {
        for (error, expected) in [
            (
                MintError::InsufficientFunds {
                    required: 20_002,
                    available: 5,
                },
                Spent::Nothing,
            ),
            (MintError::Rejected("DOUBLE_SPEND".into()), Spent::Nothing),
            (MintError::Locked, Spent::Nothing),
            (
                MintError::Journal("already in progress".into()),
                Spent::Nothing,
            ),
            (
                MintError::ChainUnreachable("connection refused".into()),
                Spent::Unknown {
                    detail: "connection refused".to_owned(),
                },
            ),
        ] {
            let ceremony = ScriptedCeremony::refusing(error);

            let (outcome, steps) = drive(&ceremony, Watch::default());

            let Creation::Stopped(stopped) = outcome else {
                panic!("a refused beginning is not a created profile");
            };
            assert_eq!(stopped.spent, expected);
            assert_eq!(stopped.reached, None, "nothing reached the chain");
            assert_eq!(ceremony.records.get(), 0);
            assert_eq!(ceremony.advanced.get(), 0, "a refused begin is not polled");
            assert!(steps.is_empty(), "nothing happened, so nothing is reported");
        }
    }

    /// **A mint whose write did not land is reported as possibly-forgotten, and as UNKNOWN money.**
    ///
    /// Makes impossible: telling somebody nothing happened when the door's own error says the mint
    /// went ahead and only the record did not. That sentence is what invites a second paid mint.
    #[test]
    fn a_mint_this_machine_may_forget_says_so() {
        let ceremony = ScriptedCeremony {
            begins: RefCell::new(Some(Err(MintDoorError {
                mint: None,
                persisted: PersistOutcome::NotWritten(
                    crate::account::profile_session::ProfileError::Corrupt(
                        "the registry file is unwritable".to_owned(),
                    ),
                ),
            }))),
            advances: RefCell::new(Vec::new()),
            forever: RefCell::new(None),
            records: std::cell::Cell::default(),
            advanced: std::cell::Cell::default(),
            record_fails: None,
        };

        let (outcome, _) = drive(&ceremony, Watch::default());

        let Creation::Stopped(stopped) = outcome else {
            panic!("an unwritten mint is not a created profile");
        };
        assert!(stopped.may_be_forgotten);
        assert!(
            matches!(stopped.spent, Spent::Unknown { .. }),
            "a mint that went ahead and was not written down has moved money for all we know"
        );
        assert!(
            copy::stopped_body(&stopped).contains("Do not start another one"),
            "the one thing this window must say"
        );
    }

    /// **Transient unreachable-chain faults are absorbed and the creation still completes; a fault
    /// storm past the tolerance stops it.**
    ///
    /// Both legs matter. Without the first, a driver that stopped on the first hiccup would pass;
    /// without the second, one that ignored every fault forever would.
    #[test]
    fn a_flaky_chain_does_not_lose_a_paid_mint_but_does_not_spin_forever() {
        let flaky = ScriptedCeremony::with_faults_before_each_answer(3);
        let (outcome, _) = drive(
            &flaky,
            Watch {
                polls: 50,
                tolerated_faults: 5,
            },
        );
        assert!(
            matches!(outcome, Creation::Created { .. }),
            "three unreachable polls must not throw away a mint that then confirms"
        );

        let storm = ScriptedCeremony::with_faults_before_each_answer(9);
        let (outcome, _) = drive(
            &storm,
            Watch {
                polls: 50,
                tolerated_faults: 5,
            },
        );
        let Creation::Stopped(stopped) = outcome else {
            panic!("a chain that never answers cannot produce a profile");
        };
        assert_eq!(stopped.reached, Some(submitted()));
        assert!(matches!(stopped.spent, Spent::Unknown { .. }));
    }

    /// **A decided refusal mid-flight stops immediately rather than being retried.**
    ///
    /// The counterpart of the tolerance above: `Journal` and `Locked` are answers, not weather, and
    /// re-asking cannot change them. The assertion is on the ADVANCE COUNT, because a driver that
    /// retried them would still stop eventually and reach the same verdict.
    #[test]
    fn a_decided_refusal_is_not_retried() {
        let ceremony = ScriptedCeremony {
            begins: RefCell::new(Some(Ok(Reached::Underway(submitted())))),
            advances: RefCell::new(vec![Err(fault(MintError::Locked))]),
            forever: RefCell::new(None),
            records: std::cell::Cell::default(),
            advanced: std::cell::Cell::default(),
            record_fails: None,
        };

        let (outcome, _) = drive(
            &ceremony,
            Watch {
                polls: 50,
                tolerated_faults: 20,
            },
        );

        assert_eq!(
            ceremony.advanced.get(),
            1,
            "a locked account is an answer; asking it fifty times is not"
        );
        let Creation::Stopped(stopped) = outcome else {
            panic!("a refusal is not a created profile");
        };
        assert!(
            matches!(stopped.spent, Spent::Unknown { .. }),
            "the DID was already pushed, so the money is unknown whatever the later fault said"
        );
    }

    /// **A confirmation whose RECORD fails is reported as spent-for-certain, not as a failure.**
    ///
    /// Makes impossible: a window telling somebody nothing happened while their DID and store are
    /// both on chain. The profile exists; only this machine's note of it does not.
    #[test]
    fn a_confirmed_profile_that_cannot_be_recorded_still_says_the_money_moved() {
        let ceremony = ScriptedCeremony {
            record_fails: Some(MintError::Journal("already registered".into())),
            ..ScriptedCeremony::walks_the_ladder()
        };

        let (outcome, _) = drive(&ceremony, Watch::default());

        let Creation::Stopped(stopped) = outcome else {
            panic!("a record that failed did not create a profile on this machine");
        };
        assert_eq!(ceremony.records.get(), 1);
        assert_eq!(stopped.spent, Spent::Committed);
        assert_eq!(
            stopped.reached,
            Some(CreationStep::Confirmed(confirmed_profile()))
        );
        let body = copy::stopped_body(&stopped);
        assert!(
            body.contains("already cost you"),
            "a stopped creation with both halves on chain must not imply the money is safe"
        );
    }

    /// **No copy on this path ever promises that nothing has been spent, unless nothing has.**
    ///
    /// The funding window carries that promise honestly because it spends nothing. This module's
    /// windows are reached only AFTER a ceremony has begun, so the sentence would be a claim about
    /// money that no read supports — the one defect class that stops a release.
    #[test]
    fn no_creation_copy_promises_untouched_funds_where_money_may_have_moved() {
        for spent in [
            Spent::Unknown {
                detail: "no route to host".to_owned(),
            },
            Spent::Committed,
        ] {
            let body = copy::stopped_body(&Stopped {
                reached: Some(submitted()),
                spent,
                why: "the node stopped answering".to_owned(),
                may_be_forgotten: false,
            });
            for promise in ["NOTHING HAS BEEN SPENT", "No money left your wallet", "untouched"] {
                assert!(
                    !body.contains(promise),
                    "a creation that may have spent money said {promise:?}"
                );
            }
        }

        // Control: where nothing WAS spent, the reassurance must genuinely appear — otherwise a copy
        // function returning the empty string would pass the whole test above.
        let nothing = copy::stopped_body(&Stopped {
            reached: None,
            spent: Spent::Nothing,
            why: "this wallet cannot pay for a profile".to_owned(),
            may_be_forgotten: false,
        });
        assert!(nothing.contains("No money left your wallet"));
    }

    /// **The created window names the evidence a person can look up themselves.**
    ///
    /// A success screen that only said "done" would be indistinguishable from one this app invented,
    /// which is exactly the claim the unforgeability property exists to prevent it from making.
    #[test]
    fn the_created_window_names_its_evidence() {
        let body = copy::created_body(&confirmed_profile());

        for fact in [DID_COIN, "did:chia:1exampleprofile", "5412009", "0xstore"] {
            assert!(body.contains(fact), "the created window omitted {fact}");
        }
    }
}
