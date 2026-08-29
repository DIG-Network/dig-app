//! The automated-spend audit record, as dig-app reads it (dig_ecosystem#3166, dig-app#289).
//!
//! # Why this module exists, and what it is NOT
//!
//! dig-node signs some spends **without asking**. It has to: the mirror-coin collateral cycle runs
//! once a weekly epoch per maintained store, and a cycle that stopped for a human to click approve
//! would not be a cycle. That is a real carve-out from §908's "the node signs nothing", and the
//! price of it is stated plainly: **the user cannot authorize each spend, so they must be able to
//! audit every one.** This module is that audit surface. It is not a log view.
//!
//! # Read, never own
//!
//! The record lives in **dig-node** ([`dig-node#376`]), because a headless node with no app attached
//! still moves the user's money and must still be auditable. `dign` reads it from the CLI and this
//! module reads it over the loopback control plane. **One record, two views** — never two records
//! that have to agree, because two bookkeepings of one set of spends is a discrepancy waiting for
//! the worst possible moment to appear.
//!
//! So nothing here persists, caches to disk, or reconstructs an entry from local state. If the node
//! cannot be asked, the honest answer is [`ActivityReading::Unknown`] — never an empty list.
//!
//! [`dig-node#376`]: https://github.com/DIG-Network/dig-node/issues/376
//!
//! # Generic over the KIND from the first commit
//!
//! Mirror-coin collateral is the **first** producer of automated spends, not the subject of this
//! record. A record shaped around mirror coins grows a second tab when the next producer arrives and
//! a third after that, and the one property that makes automatic signing defensible — a single place
//! where everything spent on the user's behalf is visible — is exactly the property that splitting
//! destroys. So [`SpendKind`] carries an `Other` arm and every renderer here goes through
//! [`SpendKind::summary`]: a producer dig-app has never heard of still renders as a legible entry
//! rather than being dropped for being unrecognised. **Dropping an unknown kind would hide a spend,
//! which is the failure this whole surface exists to prevent.**
//!
//! # Confirmed is a claim about the CHAIN
//!
//! [`SpendOutcome::Confirmed`] may only be built from a chain confirmation, and it is the only arm
//! that can produce a chain reference ([`AutomatedSpend::chain_reference`]). The legacy servers got
//! this wrong in a way worth naming: one path wrote the local record *before* broadcasting and
//! another wrote it again after, so their own bookkeeping listed coins that may never have existed.
//! Under automatic signing that is the money-lie class — a surface asserting the chain did something
//! it did not.
//!
//! [`SpendOutcome::Submitted`] is the honest middle: signed and broadcast, not yet seen on chain.
//! It renders as in-flight and offers no explorer link, because there may be nothing at the other
//! end of one.
//!
//! # Failures are entries, not omissions
//!
//! A spend that did **not** happen because the wallet was short is the single entry a person most
//! needs to see, and it is the same state the out-of-funds notification reports ([`self::funding`]).
//! A record that lists only successes makes a blocked node look like an idle one, and an idle node
//! looks fine.

pub mod control;
pub mod funding;
pub mod poller;
pub mod runway;

use crate::amount::amount_with_unit;
use crate::wallet::state::Asset;

/// What an automated spend was FOR.
///
/// The variants dig-app can name get first-class wording; everything else arrives as
/// [`Other`](Self::Other) and is still shown. See the module docs on why an unknown kind is
/// rendered rather than dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendKind {
    /// Locking collateral so a maintained store is advertised on chain — the first producer.
    MirrorCoinCollateral,
    /// Releasing collateral for a store the node no longer maintains.
    ///
    /// Distinct from [`MirrorCoinCollateral`](Self::MirrorCoinCollateral) rather than a direction
    /// flag on it, because the two move money in OPPOSITE directions and a person scanning the tab
    /// is reading for exactly that: money that left against money that came back.
    MirrorCoinReclaim,
    /// A producer this version of dig-app does not know by name, carried verbatim from the node.
    ///
    /// The node's own wording is used unchanged, because inventing a friendlier phrase for a kind
    /// dig-app has never seen would be inventing a claim about what the money did.
    Other(String),
}

impl SpendKind {
    /// The node's stable wire word for this kind.
    pub fn wire_word(&self) -> &str {
        match self {
            Self::MirrorCoinCollateral => "mirror-coin.collateral",
            Self::MirrorCoinReclaim => "mirror-coin.reclaim",
            Self::Other(word) => word,
        }
    }

    /// Read a kind off the wire. An unrecognised word becomes [`Other`](Self::Other), never an
    /// error — a node newer than this app must not be able to make an entry vanish.
    pub fn from_wire(word: &str) -> Self {
        match word {
            "mirror-coin.collateral" => Self::MirrorCoinCollateral,
            "mirror-coin.reclaim" => Self::MirrorCoinReclaim,
            other => Self::Other(other.to_string()),
        }
    }

    /// One short line saying what this spend was for, in a person's words.
    pub fn summary(&self) -> String {
        match self {
            Self::MirrorCoinCollateral => "Locked collateral so a store is advertised".to_string(),
            Self::MirrorCoinReclaim => "Released collateral for a store no longer kept".to_string(),
            Self::Other(word) => format!("Automated spend: {word}"),
        }
    }
}

/// Why a spend did not complete. **One variant per remedy**, because the reason is the only thing
/// telling a person whether to add funds, wait, or look at their node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendFailure {
    /// The wallet did not hold enough of the asset. This is the state the out-of-funds notification
    /// reports, and the two must never disagree about it.
    InsufficientFunds,
    /// The chain rejected the bundle.
    Rejected(String),
    /// Something else, in the node's own words.
    Other(String),
}

impl SpendFailure {
    /// What a person should read as the reason.
    pub fn summary(&self) -> String {
        match self {
            Self::InsufficientFunds => "Not enough funds".to_string(),
            Self::Rejected(why) => format!("Rejected by the network: {why}"),
            Self::Other(why) => why.clone(),
        }
    }
}

/// **How far a spend got before it failed — which decides whether money may have moved.**
///
/// # This distinction is the whole reason the enum exists
///
/// "Failed" reads as "it did not happen", and for exactly one of these stages that is true. The other
/// two are stages at which the node had **already signed and put a bundle on the wire**, so the money
/// may well have moved and nobody knows. Rendering those as "nothing was spent" is the money-lie
/// class — and this tab is the accountability surface for spends the user never approved, which makes
/// it the worst possible place to make that claim.
///
/// So [`may_have_moved_money`](Self::may_have_moved_money) is the predicate every renderer asks, and
/// only [`BeforeSigning`](Self::BeforeSigning) answers `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureStage {
    /// It failed before anything was signed — no bundle existed, so nothing can have reached the
    /// chain. **The only stage at which "nothing was spent" is a true statement.** The out-of-funds
    /// case lives here: a wallet too short to build the spend never built one.
    BeforeSigning,
    /// The bundle was signed and the broadcast itself failed.
    ///
    /// **Not safe to call un-spent.** A broadcast can fail on the response while the bundle has
    /// already reached a peer, so the network may hold it. The honest reading is "we do not know".
    Broadcast,
    /// The bundle was signed and broadcast, and no confirmation arrived within the window.
    ///
    /// **The most misleading one to call failed**: a confirmation that has not arrived is routinely a
    /// confirmation that is merely late, and the coin may exist right now.
    Confirmation,
}

impl FailureStage {
    /// Whether the money may already have moved despite this failure.
    ///
    /// The single predicate every surface goes through, so this judgement is made once rather than
    /// re-derived — a second copy is how one surface ends up saying "nothing was spent" while another
    /// says "we do not know" about the same entry.
    pub fn may_have_moved_money(self) -> bool {
        match self {
            Self::BeforeSigning => false,
            Self::Broadcast | Self::Confirmation => true,
        }
    }

    /// The node's stable wire word.
    pub fn wire_word(self) -> &'static str {
        match self {
            Self::BeforeSigning => "before-signing",
            Self::Broadcast => "broadcast",
            Self::Confirmation => "confirmation",
        }
    }

    /// Read a stage off the wire.
    ///
    /// **An unrecognised stage is [`Confirmation`](Self::Confirmation), not
    /// [`BeforeSigning`](Self::BeforeSigning)** — deliberately the pessimistic arm. A stage this app
    /// does not recognise is one a newer node introduced, and guessing "nothing happened" about it
    /// would make an unknown state assert the one thing it cannot support. Failing towards "we do not
    /// know" costs a cautious sentence; failing the other way is a lie about money.
    pub fn from_wire(word: &str) -> Self {
        match word {
            "before-signing" => Self::BeforeSigning,
            "broadcast" => Self::Broadcast,
            _ => Self::Confirmation,
        }
    }
}

/// What became of an automated spend.
///
/// # Five arms, and none of them may be collapsed
///
/// Each pair that looks mergeable has a real defect behind keeping it apart:
///
/// * [`Submitted`](Self::Submitted) into [`Confirmed`](Self::Confirmed) — the legacy defect in this
///   module's own docs: a record that lists coins which may never have existed.
/// * [`Submitted`](Self::Submitted) into [`Failed`](Self::Failed) — reports money as un-spent while
///   it is in flight.
/// * [`Unresolved`](Self::Unresolved) into [`Failed`](Self::Failed) — **"the node signed and does not
///   know" is not "it did not happen".** The node's record keeps these apart precisely because money
///   may well have moved, and this view must not undo that in transit.
/// * [`Failed`](Self::Failed) losing its [`FailureStage`] — see that type; two of its three stages
///   cannot honestly be called un-spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendOutcome {
    /// Recorded, and not yet signed or broadcast. Nothing has reached the network.
    Pending,
    /// Signed and broadcast; the chain has not shown it yet. **Not a claim that it happened.**
    Submitted,
    /// Seen on chain at `height`, creating the coin named by `coin_id`.
    ///
    /// The only arm that can produce a [`chain_reference`](AutomatedSpend::chain_reference), and it
    /// carries the coin id **inside the variant** so a confirmation height cannot exist without a
    /// confirmation. That shape is the node record's own (dig-node#378) and is preserved rather than
    /// flattened into a nullable height beside a status word, which is exactly how the guarantee
    /// would be lost crossing the wire.
    Confirmed {
        /// The peak height at which the spend was observed.
        height: u32,
        /// The coin id a person can paste into an explorer, as lowercase hex with no `0x`.
        coin_id: String,
    },
    /// It did not complete, how far it got, and why.
    Failed {
        /// How far it got — which decides whether money may already have moved.
        stage: FailureStage,
        /// Why, in terms a person can act on.
        reason: SpendFailure,
    },
    /// **The node signed and does not know what happened.**
    ///
    /// Produced when a producer returned early, panicked, or was killed between signing and settling.
    /// It is neither a success nor a failure, and flattening it into either is a claim about the
    /// user's money that nobody measured.
    Unresolved,
}

impl SpendOutcome {
    /// The one word the outcome column shows.
    ///
    /// Note what the two unknown arms are NOT called. `Unresolved` is "Outcome unknown" rather than
    /// "Failed", and a post-signing failure is "May have gone through" rather than "Failed", because
    /// the word is the part a person reads at a glance and it must not be the part that lies.
    pub fn word(&self) -> &'static str {
        match self {
            Self::Pending => "Not sent yet",
            Self::Submitted => "In flight",
            Self::Confirmed { .. } => "Confirmed",
            Self::Failed { stage, .. } if stage.may_have_moved_money() => "May have gone through",
            Self::Failed { .. } => "Did not happen",
            Self::Unresolved => "Outcome unknown",
        }
    }

    /// Whether this outcome is a positive statement that the chain did the thing.
    ///
    /// Used by every renderer instead of a local `matches!`, so "did it happen" is decided once.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }

    /// Whether this app can honestly say the money did NOT move.
    ///
    /// **True for very few outcomes, and that is the point.** Only a spend that never left this
    /// machine qualifies. Every renderer asks this instead of testing for `Failed`, because testing
    /// for `Failed` is precisely the mistake — it treats two stages that put a signed bundle on the
    /// wire as though nothing had left the building.
    pub fn is_certainly_unspent(&self) -> bool {
        match self {
            Self::Pending => true,
            Self::Failed { stage, .. } => !stage.may_have_moved_money(),
            Self::Submitted | Self::Confirmed { .. } | Self::Unresolved => false,
        }
    }

    /// Whether the record has settled on an answer, or is still open.
    ///
    /// `Unresolved` and a post-signing failure are **not** settled: the chain may yet show the coin,
    /// and a reconcile against chain is what closes them. Only a confirmation and a
    /// never-signed failure are genuinely over.
    pub fn is_settled(&self) -> bool {
        match self {
            Self::Confirmed { .. } => true,
            Self::Failed { stage, .. } => !stage.may_have_moved_money(),
            Self::Pending | Self::Submitted | Self::Unresolved => false,
        }
    }
}

/// One spend the node made without asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomatedSpend {
    /// When the node acted, as a unix second.
    pub at_unix: u64,
    /// What it was for.
    pub kind: SpendKind,
    /// Which asset moved.
    pub asset: Asset,
    /// How much, in that asset's base units. Rendered through [`crate::amount`] and never here, so
    /// the $DIG/XCH decimal difference has exactly one implementation.
    pub base_units: u64,
    /// Which store this was on behalf of, when the producer names one.
    pub store: Option<String>,
    /// The fee, in mojos. Always XCH, whatever `asset` the spend moves — which is why a wallet with
    /// $DIG and no XCH can be unable to spend it, and unable to reclaim what it already locked.
    pub fee_mojos: u64,
    /// The coin the spend was INTENDED to create, when the producer named one.
    ///
    /// # Kept apart from a confirmed coin id, deliberately
    ///
    /// This is what the node MEANT to create; [`SpendOutcome::Confirmed`]'s is what the chain was
    /// SEEN to contain. The node's record keeps them as distinct types because the legacy
    /// implementation confused them and waited on the wrong one, and a view that merged them here
    /// would re-introduce the confusion one layer up. A renderer must present this one as *expected*
    /// and never as evidence — see [`expected_coin`](Self::expected_coin).
    pub intended_coin_id: Option<String>,
    /// What became of it.
    pub outcome: SpendOutcome,
}

impl AutomatedSpend {
    /// The chain reference a person can check in an explorer, or `None` when there is nothing
    /// truthful to offer.
    ///
    /// # Why this is a method and not a field
    ///
    /// A field could hold a coin id beside a `Failed` outcome, and a renderer reading the field
    /// would then offer an explorer link for a spend that never reached the chain — a link that
    /// resolves to nothing, attached to money the user is being told did not move. Deriving it from
    /// the outcome makes that state unrepresentable rather than merely discouraged.
    pub fn chain_reference(&self) -> Option<&str> {
        match &self.outcome {
            SpendOutcome::Confirmed { coin_id, .. } => Some(coin_id.as_str()),
            SpendOutcome::Pending
            | SpendOutcome::Submitted
            | SpendOutcome::Failed { .. }
            | SpendOutcome::Unresolved => None,
        }
    }

    /// The amount with its unit, as one phrase (`20 $DIG`).
    pub fn amount(&self) -> String {
        amount_with_unit(self.asset, self.base_units)
    }

    /// The coin a person could go LOOK for, on an entry the chain has not confirmed.
    ///
    /// # Why an unconfirmed entry still offers something to check
    ///
    /// The outcomes that may have moved money — `Submitted`, `Unresolved`, and a post-signing
    /// failure — are exactly the ones where a person most wants to go and find out for themselves,
    /// and the node knows which coin they should be looking for. Withholding it would leave the tab
    /// saying "this may have gone through" with no way to resolve the question.
    ///
    /// It is `None` on a confirmed entry, because there [`chain_reference`](Self::chain_reference)
    /// carries the coin the chain was actually SEEN to hold, and offering both would invite a
    /// renderer to show an expectation beside evidence as though they were the same claim. It is
    /// also `None` where the money certainly did not move, because there is nothing to look for.
    ///
    /// **A caller MUST label this as expected rather than observed.** It matches `dign`'s own
    /// rendering, which prints `~<id> (expected)` against `#<id>` for an observed coin — one record,
    /// two views, and they must not describe it differently.
    pub fn expected_coin(&self) -> Option<&str> {
        if self.outcome.is_confirmed() || self.outcome.is_certainly_unspent() {
            return None;
        }
        self.intended_coin_id.as_deref()
    }
}

/// How much is locked up right now, and against how many stores.
///
/// Shown at the head of the tab so the figure can be checked against the wallet: with 20 $DIG per
/// collateralised store, `stores × 20` is a number a person can verify independently, which is the
/// point of publishing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LockedTotal {
    /// How many stores currently hold collateral.
    pub stores: u32,
    /// The total locked, in the collateral asset's base units.
    pub base_units: u64,
}

impl LockedTotal {
    /// The head-of-tab sentence, naming both the total and what it is against.
    pub fn sentence(&self, asset: Asset) -> String {
        match self.stores {
            0 => "Nothing is locked up.".to_string(),
            1 => format!(
                "{} locked against 1 store.",
                amount_with_unit(asset, self.base_units)
            ),
            n => format!(
                "{} locked against {n} stores.",
                amount_with_unit(asset, self.base_units)
            ),
        }
    }
}

/// The whole record, as one answer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActivityLedger {
    /// The spends, newest first — the order a person reads.
    pub spends: Vec<AutomatedSpend>,
    /// What is locked right now.
    pub locked: LockedTotal,
    /// How many lines of the node's audit trail could not be parsed.
    ///
    /// # A truncated trail must not present as a complete one
    ///
    /// The node's record is append-only JSONL and it COUNTS the lines it could not read rather than
    /// skipping them silently, because a corrupt trail that renders as a tidy shorter one is the same
    /// lie as a missing entry — and on this surface a missing entry is invisible money movement.
    /// Carrying the count across the wire is what lets the tab say "some of this record could not be
    /// read" instead of quietly showing less than there is.
    ///
    /// # `None` is NOT zero, and that distinction is the whole point of the field
    ///
    /// `None` means **the node did not tell us**; `Some(0)` means it said the trail was wholly
    /// readable. Collapsing the two answers "nothing is missing" on the strength of no answer at
    /// all, which is precisely the claim this field exists to prevent -- the same shape as
    /// [`BalanceReading::Unknown`](crate::wallet::overview::BalanceReading::Unknown), where an
    /// unknown is never rendered as a number a person could act on.
    ///
    /// It was a bare `u64` defaulting to `0` on an absent key, which is how a corrupt audit trail
    /// came to render as a tidy empty one (dig-app#289).
    pub unreadable_lines: Option<u64>,
}

impl ActivityLedger {
    /// Whether the node SAID every line of its trail was readable.
    ///
    /// The predicate the pane asks before it presents the list as the whole story. An unknown count
    /// is **not** complete: the pane must qualify a list it cannot vouch for, and answering `true`
    /// here would be the reassuring-default this type was changed to make unrepresentable.
    pub fn is_complete(&self) -> bool {
        self.unreadable_lines == Some(0)
    }
}

/// Why no audit record is available. One variant per REMEDY.
#[cfg_attr(test, derive(strum::EnumIter))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivityUnknown {
    /// No node is connected, so there is nothing to ask.
    NoNode,
    /// A node answered, and does not serve this method.
    ///
    /// **Structurally separate from an empty ledger, and that is the whole reason this variant
    /// exists.** A node too old to keep the record and a node that has genuinely spent nothing print
    /// the same empty list, and only one of those means "no money has moved". Rendering the first as
    /// the second tells a person their node has spent nothing when the truth is that nobody knows.
    NotSupported,
    /// The node refused the call — typically no control token on this machine.
    Refused,
    /// The node answered with something this app could not read.
    Unreadable,
}

impl ActivityUnknown {
    /// What the pane says, naming the remedy rather than the fault.
    pub fn remedy(&self) -> &'static str {
        match self {
            Self::NoNode => "Start the DIG node to see what it has spent.",
            Self::NotSupported => {
                "This node is too old to keep an audit record. Update it to see automated spends."
            }
            Self::Refused => "DIG could not authenticate to the node on this computer.",
            Self::Unreadable => "The node answered with a record DIG could not read.",
        }
    }
}

/// The audit record's four states, which are the four async states of the tab.
///
/// [`Pending`](Self::Pending) is the default rather than an empty [`Known`](Self::Known): before
/// anything has been asked, "this node has spent nothing" is not a thing anybody has measured.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ActivityReading {
    /// A read is under way. Nothing has failed, so naming a reason would invent one.
    ///
    /// The DEFAULT, marked on the variant so the choice sits beside the thing it describes: an
    /// unasked question is pending, never an empty ledger.
    #[default]
    Pending,
    /// The node answered. An EMPTY ledger is a real answer: this node has made no automated spends.
    Known(ActivityLedger),
    /// No record could be read, and which thing was missing.
    Unknown(ActivityUnknown),
}

impl ActivityReading {
    /// Whether this reading is a positive statement that the node has spent nothing.
    ///
    /// Only a `Known` empty ledger qualifies. Everything else is an absence of knowledge, and the
    /// distinction is what keeps the empty state from being drawn over an outage.
    pub fn is_known_empty(&self) -> bool {
        matches!(self, Self::Known(ledger) if ledger.spends.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn confirmed(coin: &str) -> SpendOutcome {
        SpendOutcome::Confirmed {
            height: 9_172_077,
            coin_id: coin.to_string(),
        }
    }

    /// A spend that varies ONLY in its outcome.
    ///
    /// It always carries an `intended_coin_id`, deliberately: the nearest wrong implementation hands
    /// out a coin id from the entry regardless of outcome, and a fixture whose unconfirmed entries
    /// had no coin id anywhere could not tell that implementation from a correct one.
    fn spend(outcome: SpendOutcome) -> AutomatedSpend {
        AutomatedSpend {
            at_unix: 1_787_500_000,
            kind: SpendKind::MirrorCoinCollateral,
            asset: Asset::DIG,
            base_units: 20_000,
            store: Some("store-a".to_string()),
            fee_mojos: 1_000_000,
            intended_coin_id: Some("intended99".to_string()),
            outcome,
        }
    }

    /// A failure at `stage`, with a reason that is the same in every case so the STAGE is the only
    /// thing varying.
    fn failed_at(stage: FailureStage) -> SpendOutcome {
        SpendOutcome::Failed {
            stage,
            reason: SpendFailure::InsufficientFunds,
        }
    }

    /// **Only a confirmed spend offers a chain reference.**
    ///
    /// The nearest wrong implementation carries the coin id as a field on the entry and hands it out
    /// regardless of outcome — which is why the fixture varies ONLY the outcome across three spends
    /// that are otherwise identical, including a failed one built from a producer that DID mint a
    /// coin id. A fixture whose failed entry had no coin id anywhere could not tell the two
    /// implementations apart.
    #[test]
    fn a_reference_is_offered_only_where_the_chain_confirmed_it() {
        assert_eq!(
            spend(confirmed("ab12")).chain_reference(),
            Some("ab12"),
            "a confirmed spend is checkable in an explorer"
        );
        assert_eq!(
            spend(SpendOutcome::Submitted).chain_reference(),
            None,
            "an in-flight spend has nothing on chain to link to yet"
        );
        for unproven in [
            failed_at(FailureStage::BeforeSigning),
            failed_at(FailureStage::Broadcast),
            failed_at(FailureStage::Confirmation),
            SpendOutcome::Unresolved,
            SpendOutcome::Pending,
        ] {
            assert_eq!(
                spend(unproven.clone()).chain_reference(),
                None,
                "{unproven:?} was never seen on chain, so it must not offer evidence"
            );
        }
    }

    /// **A failure after signing is NEVER reported as money that did not move.**
    ///
    /// This is the money-lie guard, and it is the reason [`FailureStage`] exists. All three arms are
    /// swept together because the fixture varies ONLY the stage — same reason, same amount, same
    /// everything — so the assertion cannot pass by the three entries differing incidentally. The
    /// `BeforeSigning` arm is the truthful control: without it this test would also pass on an
    /// implementation that simply never claims anything is unspent, which would be useless in the
    /// opposite direction.
    #[test]
    fn only_a_spend_that_never_left_this_machine_is_called_unspent() {
        assert!(
            spend(failed_at(FailureStage::BeforeSigning))
                .outcome
                .is_certainly_unspent(),
            "a spend that was never signed genuinely did not happen"
        );
        for risky in [FailureStage::Broadcast, FailureStage::Confirmation] {
            assert!(
                !spend(failed_at(risky)).outcome.is_certainly_unspent(),
                "{risky:?} put a signed bundle on the wire; calling it unspent is a lie about money"
            );
            assert!(risky.may_have_moved_money());
        }
        assert!(
            !spend(SpendOutcome::Unresolved)
                .outcome
                .is_certainly_unspent(),
            "the node signed and does not know — that is not 'it did not happen'"
        );
        assert!(
            !spend(SpendOutcome::Submitted)
                .outcome
                .is_certainly_unspent(),
            "in flight is not un-spent"
        );
    }

    /// **The WORD a person reads never says a post-signing failure did not happen.**
    ///
    /// Separate from the predicate above because the predicate can be right while the copy is wrong,
    /// and the copy is the part anybody actually sees. Only the never-signed arm may use the
    /// did-not-happen wording, and the two unknown arms must not be called "Failed" at all.
    #[test]
    fn the_outcome_word_does_not_overclaim() {
        assert_eq!(
            spend(failed_at(FailureStage::BeforeSigning)).outcome.word(),
            "Did not happen"
        );
        for risky in [FailureStage::Broadcast, FailureStage::Confirmation] {
            let word = spend(failed_at(risky)).outcome.word();
            assert_eq!(word, "May have gone through", "{risky:?}");
            assert!(
                !word.to_lowercase().contains("did not"),
                "{risky:?}: {word}"
            );
        }
        let unresolved = spend(SpendOutcome::Unresolved).outcome.word();
        assert_eq!(unresolved, "Outcome unknown");
        assert!(
            !unresolved.to_lowercase().contains("fail"),
            "'signed and don't know' is not a failure: {unresolved}"
        );
    }

    /// **An unrecognised failure stage fails towards "we do not know", never towards "nothing
    /// happened".**
    ///
    /// A stage this build does not know is one a newer node introduced. Guessing `BeforeSigning`
    /// would make an unknown state assert the one claim it cannot support — and it would do so
    /// silently, on a money surface, for exactly the entries a newer node thought worth adding.
    #[test]
    fn an_unknown_failure_stage_is_pessimistic() {
        let unknown = FailureStage::from_wire("some-future-stage");
        assert!(
            unknown.may_have_moved_money(),
            "an unknown stage must not be assumed harmless"
        );
        assert_eq!(unknown, FailureStage::Confirmation);
        // The control: the known words still resolve to themselves, or the pessimism above would be
        // the whole function rather than its fallback.
        for stage in [
            FailureStage::BeforeSigning,
            FailureStage::Broadcast,
            FailureStage::Confirmation,
        ] {
            assert_eq!(FailureStage::from_wire(stage.wire_word()), stage);
        }
    }

    /// **An unconfirmed spend still offers the coin to go LOOK for**, so "this may have gone through"
    /// is a question a person can resolve rather than a dead end.
    ///
    /// A confirmed spend offers `None` here, because there the chain reference carries what was
    /// actually seen — and showing an expectation beside evidence invites a renderer to present them
    /// as the same claim.
    #[test]
    fn an_unresolved_spend_names_the_coin_to_look_for() {
        for open in [
            SpendOutcome::Submitted,
            SpendOutcome::Unresolved,
            failed_at(FailureStage::Broadcast),
            failed_at(FailureStage::Confirmation),
        ] {
            assert_eq!(
                spend(open.clone()).expected_coin(),
                Some("intended99"),
                "{open:?} may have landed, so there is something to go and check"
            );
        }
        assert_eq!(
            spend(confirmed("ab12")).expected_coin(),
            None,
            "a confirmed spend has evidence; an expectation beside it would read as a second claim"
        );
        assert_eq!(
            spend(failed_at(FailureStage::BeforeSigning)).expected_coin(),
            None,
            "nothing was signed, so there is no coin to look for"
        );
    }

    /// **An unknown outcome is not settled**, so a reconcile still has work to do on it.
    #[test]
    fn only_a_decided_outcome_is_settled() {
        assert!(spend(confirmed("ab12")).outcome.is_settled());
        assert!(spend(failed_at(FailureStage::BeforeSigning))
            .outcome
            .is_settled());
        for open in [
            SpendOutcome::Pending,
            SpendOutcome::Submitted,
            SpendOutcome::Unresolved,
            failed_at(FailureStage::Broadcast),
            failed_at(FailureStage::Confirmation),
        ] {
            assert!(!spend(open.clone()).outcome.is_settled(), "{open:?}");
        }
    }

    /// **A trail with unreadable lines does not present as complete.**
    #[test]
    fn a_truncated_trail_says_so() {
        assert!(ActivityLedger::default().is_complete());
        let damaged = ActivityLedger {
            unreadable_lines: 2,
            ..Default::default()
        };
        assert!(
            !damaged.is_complete(),
            "a corrupt trail rendering as a tidy shorter one is the same lie as a missing entry"
        );
    }

    /// **A confirmed outcome cannot be built without the coin id**, so "confirmed with nothing to
    /// check" is unrepresentable rather than merely discouraged. Compile-time, asserted here so the
    /// property is stated where a reader looks for it.
    #[test]
    fn confirmation_carries_its_evidence() {
        let outcome = confirmed("ff00");
        let SpendOutcome::Confirmed { height, coin_id } = &outcome else {
            panic!("built as confirmed");
        };
        assert_eq!(*height, 9_172_077);
        assert!(!coin_id.is_empty());
        assert!(outcome.is_confirmed());
        assert!(!SpendOutcome::Submitted.is_confirmed());
    }

    /// **A kind this app has never heard of still renders**, because dropping it would hide a spend.
    #[test]
    fn an_unknown_producer_is_shown_rather_than_dropped() {
        let kind = SpendKind::from_wire("some-future-producer.topup");
        assert_eq!(
            kind,
            SpendKind::Other("some-future-producer.topup".to_string())
        );
        assert!(
            kind.summary().contains("some-future-producer.topup"),
            "the node's own word survives to the surface: {}",
            kind.summary()
        );
        assert_eq!(kind.wire_word(), "some-future-producer.topup");
    }

    /// **Every known kind round-trips through the wire word**, so the tab and `dign` cannot come to
    /// disagree about what an entry is called.
    #[test]
    fn known_kinds_round_trip() {
        for kind in [
            SpendKind::MirrorCoinCollateral,
            SpendKind::MirrorCoinReclaim,
        ] {
            assert_eq!(SpendKind::from_wire(kind.wire_word()), kind);
        }
    }

    /// **An unreadable node is not an empty ledger.**
    ///
    /// Both render as "no spends listed", and only one of them means no money moved. The fixture
    /// pairs a genuinely-empty KNOWN ledger against each unknown reason so the assertion cannot pass
    /// by the two simply being different enum variants somewhere.
    #[test]
    fn only_a_measured_empty_ledger_reads_as_nothing_spent() {
        assert!(ActivityReading::Known(ActivityLedger::default()).is_known_empty());
        assert!(!ActivityReading::Pending.is_known_empty());
        for reason in [
            ActivityUnknown::NoNode,
            ActivityUnknown::NotSupported,
            ActivityUnknown::Refused,
            ActivityUnknown::Unreadable,
        ] {
            assert!(
                !ActivityReading::Unknown(reason.clone()).is_known_empty(),
                "{reason:?} is an absence of knowledge, not a measured zero"
            );
        }
    }

    /// **Before anything is asked, the reading is pending** — not an empty ledger, which would state
    /// a measurement nobody took.
    #[test]
    fn the_default_reading_asserts_nothing() {
        assert_eq!(ActivityReading::default(), ActivityReading::Pending);
        assert!(!ActivityReading::default().is_known_empty());
    }

    /// **Every unknown reason names a remedy**, or the error state is the dead end #1800 removed.
    /// Swept over the generated variant list, so a new reason arrives in this guard without anyone
    /// remembering to add it.
    #[test]
    fn every_unknown_reason_names_a_remedy() {
        use strum::IntoEnumIterator;
        for reason in ActivityUnknown::iter() {
            let remedy = reason.remedy();
            assert!(!remedy.is_empty(), "{reason:?} says nothing");
            assert!(
                remedy.ends_with('.'),
                "{reason:?} reads as a sentence: {remedy}"
            );
        }
    }

    /// **A node too old to keep the record says so**, rather than borrowing the "start your node"
    /// sentence — the remedy is an update, and the two are different actions.
    #[test]
    fn an_old_node_is_told_to_update_not_to_start() {
        let remedy = ActivityUnknown::NotSupported.remedy();
        assert!(remedy.contains("Update"), "{remedy}");
        assert!(
            !remedy.contains("Start"),
            "starting a running node fixes nothing: {remedy}"
        );
    }

    /// **The locked total is rendered through the asset-aware formatter**, so 20 $DIG reads as
    /// `20 $DIG` rather than as `0.00000002` — the #2295 defect, on a figure whose entire purpose is
    /// to be checked against the wallet.
    #[test]
    fn the_locked_total_renders_dig_at_cat_precision() {
        let locked = LockedTotal {
            stores: 3,
            base_units: 60_000,
        };
        let sentence = locked.sentence(Asset::DIG);
        assert!(sentence.contains("60 $DIG"), "{sentence}");
        assert!(sentence.contains("3 stores"), "{sentence}");
    }

    /// **One store is not "1 stores"**, and nothing locked says so plainly rather than printing a
    /// zero against a plural.
    #[test]
    fn the_locked_sentence_reads_at_every_count() {
        assert_eq!(
            LockedTotal::default().sentence(Asset::DIG),
            "Nothing is locked up."
        );
        let one = LockedTotal {
            stores: 1,
            base_units: 20_000,
        };
        assert!(
            one.sentence(Asset::DIG).contains("1 store."),
            "{}",
            one.sentence(Asset::DIG)
        );
    }

    /// **A failure is a legible entry**, not a blank cell — it is the entry a blocked user most
    /// needs, and it must name what to do about it.
    #[test]
    fn a_failure_says_what_went_wrong() {
        assert_eq!(
            SpendFailure::InsufficientFunds.summary(),
            "Not enough funds"
        );
        assert!(SpendFailure::Rejected("bad sig".into())
            .summary()
            .contains("bad sig"));
        assert_eq!(
            failed_at(FailureStage::BeforeSigning).word(),
            "Did not happen"
        );
    }

    /// **An amount is rendered by the shared formatter**, never locally — the collateral asset is a
    /// CAT at three decimals and XCH is at twelve.
    #[test]
    fn an_amount_carries_its_unit() {
        assert_eq!(spend(SpendOutcome::Submitted).amount(), "20 $DIG");
    }
}
