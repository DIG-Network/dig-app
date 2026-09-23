//! The reward-distributor CREATE card's pure state machine and sentence builders
//! (dig_ecosystem#3253 §6): warnings -> acknowledge -> manager choice -> coin picker -> terms ->
//! submit -> pending-status rendering.
//!
//! # Paint stays I/O-free; this module is where the I/O-free half lives
//!
//! `confirm::gui::window::pane::store_rewards`'s paint functions receive no chain, account or
//! publisher handle (traced: `store_rewards::disclosure(ui, at, t, live, &store_id, now)` — no
//! I/O capability anywhere in that signature), because paint must never read the chain. Every
//! other real spend in this app crosses that boundary the same way: paint returns a
//! `TrayAction`, and a dispatcher that already holds `AccountResidency`/`ChainSource`/
//! `SpendPublisher` (mirroring `wallet.rs`'s `TrayAction::Send` -> the `dig-app.rs` arm beside
//! `ProfileMint::for_session`) performs the real call. This module is the PURE half of that
//! split: sentence builders, terms validation and the one production function
//! ([`submit`]) that calls [`super::mint::DistributorMintDoor::begin`] — the dispatcher arm is
//! the only caller of `submit`, so it is also the sole indirect caller of `begin` outside
//! `mint.rs` (see `subject_tests::begin_has_exactly_one_production_caller_outside_mint_rs`).
//!
//! # No persistence
//!
//! `pending_slots()` is a process-global slot, exactly like `store_rewards::app_readings()` — it lives
//! for the process's lifetime ONLY. A restart loses every in-flight pending mint's local record;
//! the mint itself is not lost (it is already pushed and confirmable from the chain), but this
//! card's memory of having submitted it is. A future pass that wants restart-survival needs a
//! durable store, not this one.
//!
//! # The phantom-slot hazard (dig_ecosystem#3357)
//!
//! This module never calls `created_slot_value_to_slot`: a launch derives no slot at all (see
//! `super::mint`'s own doc), and nothing here rebuilds one from a chain read either.

use std::collections::HashMap;
use std::sync::Mutex;

use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin};
use chia_wallet_sdk::driver::Cat;
use dig_account::mint::MintError;
use dig_account::{PendingRewardDistributor, RewardDistributorStatus};
use dig_chainsource_interface::ChainSource;
use dig_rewards_coin::LaunchComment;

use super::copy;
use super::create::{parse_hash_hex, Launchable, ManagerChoice, ManagerChoiceMade};
use super::mint::{DistributorMintAvailability, DistributorMintDoor, DistributorMintTerms};
use super::pane::{CreationGate, WarningsShown, REQUIRED_WARNING_KEYS};

// ---------------------------------------------------------------------------------------------
// Manager-choice copy. Each arm states ONLY the verified negative -- see the module's own
// `FORBIDDEN` list below, enforced across all 14 locales by `render_path_forbidden_word_tests`.
// ---------------------------------------------------------------------------------------------

/// Arm A's rendered body -- built here, single-key, freezes forever if lost. Never claims safety
/// or recoverability.
pub fn manager_arm_a_body() -> String {
    copy::CREATE_MANAGER_ARM_A_BODY.text()
}

/// Arm B's rendered body -- DIG cannot verify the supplied hash. Never claims safety, trust or
/// recoverability either way.
pub fn manager_arm_b_body() -> String {
    copy::CREATE_MANAGER_ARM_B_BODY.text()
}

/// Arm A's rendered label -- the radio/tile title above [`manager_arm_a_body`].
pub fn manager_arm_a_label() -> String {
    copy::CREATE_MANAGER_ARM_A_LABEL.text()
}

/// Arm B's rendered label -- the radio/tile title above [`manager_arm_b_body`].
pub fn manager_arm_b_label() -> String {
    copy::CREATE_MANAGER_ARM_B_LABEL.text()
}

/// Arm B's hex-input field label -- shown only once arm B is selected.
pub fn manager_arm_b_field_label() -> String {
    copy::CREATE_MANAGER_ARM_B_FIELD.text()
}

/// The warnings-acknowledgment button's label -- the control that turns [`super::pane::WarningsShown`]
/// into [`super::pane::CreationGate`] (`CreationGate::acknowledge`).
pub fn ack_button_label() -> String {
    copy::CREATE_ACK_BUTTON.text()
}

/// Words the manager-choice render path (arm A and arm B labels + bodies) may never contain, in
/// any of the 14 locales -- DECISIONS-3253's forbidden list for this specific step (narrower than
/// `copy.rs`'s crate-wide forbidden-phrase sweep, which does not cover these keys).
pub const FORBIDDEN_MANAGER_WORDS: &[&str] = &[
    "recovery",
    "recoverable",
    "recovery-capable",
    "safe",
    "secure",
    "secured",
    "trusted",
];

// ---------------------------------------------------------------------------------------------
// Coin picker.
// ---------------------------------------------------------------------------------------------

/// One coin-picker row's rendered sentence, or `None` if `base_units` cannot be formatted for
/// `asset` (mirrors [`crate::amount::format_asset_amount`]'s own fallibility -- never a raw
/// numeral).
pub fn coin_row_sentence(asset: crate::wallet::state::Asset, base_units: u64) -> Option<String> {
    let amount = crate::amount::format_asset_amount(asset, base_units)?;
    Some(copy::CREATE_COIN_ROW.with(&crate::i18n::Args::new().text("amount", amount)))
}

/// The listing omitted `omitted` coins (a `CatTransferError` on some candidates, never silently
/// dropped). `None` when nothing was omitted.
pub fn coin_omitted_sentence(omitted: usize) -> Option<String> {
    (omitted > 0).then(|| {
        copy::CREATE_COIN_OMITTED
            .with(&crate::i18n::Args::new().text("omitted", omitted.to_string()))
    })
}

/// A locked-account coin listing -- rendered as locked, never folded into the empty-listing
/// sentence ([`coin_empty_sentence`]).
pub fn coin_locked_sentence() -> String {
    copy::CREATE_COIN_LOCKED.text()
}

/// The listing is genuinely empty (not locked, not omitted-to-zero -- zero candidates existed at
/// all).
pub fn coin_empty_sentence() -> String {
    copy::CREATE_COIN_EMPTY.text()
}

// ---------------------------------------------------------------------------------------------
// Terms validation -- refused here, before the door ever sees them (the door's own money gates
// still run independently; this is the honest-before-spend half).
// ---------------------------------------------------------------------------------------------

/// One thing wrong with a set of typed terms, refused before [`DistributorMintDoor::begin`] is
/// ever called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermsRefusal {
    /// An epoch length of zero -- unachievable; the seam itself refuses it too, but this
    /// surfaces the same refusal before a spend is attempted.
    ZeroEpoch,
    /// A first-epoch start in the past.
    FirstEpochInPast,
    /// No confirmed, unspent XCH coin was found at the minter's own puzzle hash to fund the
    /// launch.
    NoFundingCoin,
}

impl TermsRefusal {
    /// The rendered sentence for this refusal.
    pub fn sentence(&self) -> String {
        match self {
            TermsRefusal::ZeroEpoch => copy::CREATE_TERMS_EPOCH_ZERO.text(),
            TermsRefusal::FirstEpochInPast => copy::CREATE_TERMS_FIRST_EPOCH_PAST.text(),
            TermsRefusal::NoFundingCoin => copy::CREATE_TERMS_NO_FUNDING_COIN.text(),
        }
    }
}

/// The epoch-length field's label.
pub fn terms_epoch_label() -> String {
    copy::CREATE_TERMS_EPOCH_LABEL.text()
}

/// The first-epoch-start field's label.
pub fn terms_first_epoch_label() -> String {
    copy::CREATE_TERMS_FIRST_EPOCH_LABEL.text()
}

/// The network-fee field's label.
pub fn terms_fee_label() -> String {
    copy::CREATE_TERMS_FEE_LABEL.text()
}

/// Refuses an epoch length of zero and a first-epoch start before `now` -- named reasons, checked
/// before the door is ever called. Does not check funding; see [`select_funding_coin`].
pub fn validate_epoch_terms(
    distributor_epoch_seconds: u64,
    first_epoch_start: u64,
    now_unix_seconds: u64,
) -> Result<(), TermsRefusal> {
    if distributor_epoch_seconds == 0 {
        return Err(TermsRefusal::ZeroEpoch);
    }
    if first_epoch_start < now_unix_seconds {
        return Err(TermsRefusal::FirstEpochInPast);
    }
    Ok(())
}

/// Picks the XCH coin that funds the launch: the smallest confirmed, unspent candidate that
/// covers `required` mojos, or (if none covers it) the largest candidate -- mirroring
/// `dig-account`'s own `did.rs:344-418` selection so this card's choice matches the one the
/// profile-mint flow already makes. `None` when `candidates` is empty.
pub fn select_funding_coin(
    candidates: &[chia_protocol::Coin],
    required: u64,
) -> Option<chia_protocol::Coin> {
    let covering = candidates
        .iter()
        .filter(|c| c.amount >= required)
        .min_by_key(|c| c.amount);
    covering
        .copied()
        .or_else(|| candidates.iter().max_by_key(|c| c.amount).copied())
}

// ---------------------------------------------------------------------------------------------
// Submit -- the sole production caller of `DistributorMintDoor::begin` outside `mint.rs`.
// ---------------------------------------------------------------------------------------------

/// Drives `door.begin(launchable, terms)` and renders any `MintError` to the sentence a card
/// shows. `MintError::Locked` gets its own sentence (the account locked between opening the card
/// and pressing submit); every other `MintError` renders through its own `Display`, per
/// dig_ecosystem#3253 §6 acceptance item 6 -- `MintError` has no `push_attempts()` accessor as of
/// dig-account 0.30.1 (checked against the published crate source), so that specific wording from
/// the ticket's acceptance text does not apply to this version and is not implemented; the
/// `Display`-per-variant bar above covers every case `MintError` actually has.
///
/// The dispatcher arm that owns a live `AccountResidency`/`ChainSource`/`SpendPublisher` is the
/// only intended caller (see this module's doc comment); tests below call it directly with a
/// [`super::mint::DistributorMint`] fixture door, which is the exact shape that dispatcher builds.
/// The submit button's label -- "Sign and submit".
pub fn submit_button_label() -> String {
    copy::CREATE_SUBMIT_BUTTON.text()
}

/// [`copy::CREATE_BUSY`]'s rendered text -- the sentence the draft's submit handler shows when
/// [`super::create_sink::RewardCreateSink::submit`] answers [`super::create_sink::Refused::Busy`].
/// The sole production caller is [`attempt_submit`] below.
pub fn busy_sentence() -> String {
    copy::CREATE_BUSY.text()
}

pub fn submit<D: DistributorMintDoor>(
    door: D,
    launchable: Launchable,
    terms: DistributorMintTerms,
) -> Result<PendingRewardDistributor, String> {
    match door.begin(launchable, terms) {
        Ok(pending) => Ok(pending),
        Err(MintError::Locked) => Err(copy::CREATE_SUBMIT_LOCKED.text()),
        Err(other) => Err(other.to_string()),
    }
}

// ---------------------------------------------------------------------------------------------
// Pending-mint pane state -- process-global, per store id. Mirrors
// `store_rewards::app_readings()`'s shape exactly.
// ---------------------------------------------------------------------------------------------

/// The per-store pending-mint slot: the pushed [`PendingRewardDistributor`] plus the last
/// `status(&chain)` outcome, if any read has completed yet.
struct PendingCardState {
    pending: PendingRewardDistributor,
    last_status: Option<Result<RewardDistributorStatus, String>>,
}

fn pending_slots() -> &'static Mutex<HashMap<String, PendingCardState>> {
    static SLOTS: std::sync::OnceLock<Mutex<HashMap<String, PendingCardState>>> =
        std::sync::OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A store id's most recent [`submit`] failure, when it has one and no pending mint superseded it.
/// Separate from `pending_slots` because a failed submission never produced a
/// [`PendingRewardDistributor`] -- there is nothing to key a `PendingCardState` on -- so this is
/// the second place [`last_rendered`] reads, not a variant folded into the first.
fn submit_errors() -> &'static Mutex<HashMap<String, String>> {
    static ERRORS: std::sync::OnceLock<Mutex<HashMap<String, String>>> = std::sync::OnceLock::new();
    ERRORS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Stores a freshly submitted mint for `store_id`. Called by the dispatcher arm once
/// [`submit`] returns `Ok` -- never discarded, per dig_ecosystem#3253 §6 acceptance item 6. Clears
/// any earlier [`record_submit_error`] for the same store: a fresh `Ok` supersedes a stale
/// refusal, and leaving the old sentence in place would make a successful retry still read as
/// failed.
pub fn record_submission(store_id: &str, pending: PendingRewardDistributor) {
    submit_errors().lock().unwrap().remove(store_id);
    pending_slots().lock().unwrap().insert(
        store_id.to_string(),
        PendingCardState {
            pending,
            last_status: None,
        },
    );
}

/// Records `message` -- [`submit`]'s own rendered error sentence -- as the outcome for `store_id`.
/// Called by the dispatcher arm (the create-sink worker; see [`super::create_sink`]) once
/// [`submit`] returns `Err`, so the next paint shows why a submission did not become a pending
/// mint rather than showing nothing. See this module's doc comment: no publish without a witness,
/// and a refused publish is a witness too.
pub fn record_submit_error(store_id: &str, message: String) {
    submit_errors()
        .lock()
        .unwrap()
        .insert(store_id.to_string(), message);
}

/// Whether `store_id` has a pending mint recorded (paint-time, no I/O).
pub fn has_pending(store_id: &str) -> bool {
    pending_slots().lock().unwrap().contains_key(store_id)
}

/// Every store id with a pending mint recorded right now (paint-time, no I/O) -- the set the pane's
/// refresh cadence must call [`refresh_and_render`] for, so the standing condition ("no publish
/// without `status` behind it") holds for every held pending mint, not just the one on screen.
pub fn pending_store_ids() -> Vec<String> {
    pending_slots().lock().unwrap().keys().cloned().collect()
}

/// Re-reads `store_id`'s pending mint's status against `chain` (the pane's refresh cadence calls
/// this OFF the paint path, same as every other reading this crate takes) and returns the
/// sentence paint should show. Keeps the pending state on an `Err` -- never drops it, per
/// dig_ecosystem#3253 §6 acceptance item 7.
pub fn refresh_and_render<C: ChainSource + ?Sized>(store_id: &str, chain: &C) -> Option<String> {
    let mut slots = pending_slots().lock().unwrap();
    let slot = slots.get_mut(store_id)?;
    let outcome = slot.pending.status(chain).map_err(|e| e.to_string());
    let sentence = render_status(&slot.pending, &outcome);
    slot.last_status = Some(outcome);
    Some(sentence)
}

/// The last rendered sentence for `store_id`, without touching the chain (a pure paint-time read
/// of whatever [`refresh_and_render`] last recorded, or -- when no mint is pending -- whatever
/// [`record_submit_error`] last recorded).
pub fn last_rendered(store_id: &str) -> Option<String> {
    if let Some(slot) = pending_slots().lock().unwrap().get(store_id) {
        return Some(render_status(&slot.pending, slot.last_status.as_ref()?));
    }
    submit_errors().lock().unwrap().get(store_id).cloned()
}

fn render_status(
    pending: &PendingRewardDistributor,
    outcome: &Result<RewardDistributorStatus, String>,
) -> String {
    match outcome {
        Err(_) => copy::CREATE_STATUS_UNKNOWN.text(),
        Ok(RewardDistributorStatus::Confirmed(_)) => {
            // The pane's EXISTING `rewards_sections` render the live distributor from here on --
            // no new "created!" banner (dig_ecosystem#3253 §6 acceptance item 7). This is only
            // the one-time bridging sentence the pending slot shows.
            copy::CREATE_CONFIRMED.text()
        }
        Ok(RewardDistributorStatus::Awaiting { blocks_since_push }) => copy::CREATE_AWAITING.with(
            &crate::i18n::Args::new()
                .text("blocks", blocks_since_push.to_string())
                .text(
                    "predicted_id",
                    hex::encode(pending.distributor_launcher_id().to_bytes()),
                ),
        ),
        Ok(RewardDistributorStatus::Failed { reason }) => {
            copy::CREATE_FAILED.with(&crate::i18n::Args::new().text("reason", reason.clone()))
        }
    }
}

/// The chosen [`ManagerChoice`] arm's label, for the picker's two radio rows.
pub fn manager_choice_label(choice: &ManagerChoice) -> &'static str {
    match choice {
        ManagerChoice::SingleKeyBuiltHere(_) => "arm-a",
        ManagerChoice::HashSuppliedByCaller(_) => "arm-b",
    }
}

// ---------------------------------------------------------------------------------------------
// The interactive card -- draft state, cached I/O-taken inputs, and the submit handler.
//
// Paint holds NO chain/account handle (this module's own doc comment), so everything paint needs
// to draw the manager-choice/coin-picker/terms steps is either raw user input (kept here, in a
// per-store [`CardDraft`]) or a value the pane's own 10s refresh cadence read and cached (kept
// here too, as [`CachedCreateInputs`], process-wide -- the minter identity and coin listings are
// account-wide, not per-store).
// ---------------------------------------------------------------------------------------------

/// Which manager arm a draft has selected, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerArm {
    /// Arm A -- a key this app builds and holds.
    A,
    /// Arm B -- a puzzle hash the person supplies (see [`arm_b_hex`](CardDraft::arm_b_hex)).
    B,
}

/// One store's in-progress create card, holding only raw user input -- never a typed witness
/// ([`WarningsShown`], [`CreationGate`]/[`Acknowledged`](super::pane::Acknowledged),
/// [`ManagerChoiceMade`]). Those are built fresh, from this draft's booleans and strings, at the
/// moment [`attempt_submit`] runs; there is nothing dishonest about rebuilding a cheap witness
/// every frame, and it lets this struct stay plain data a paint function can freely clone.
#[derive(Debug, Clone, Default)]
pub struct CardDraft {
    /// The person pressed the "I understand" button after all five warning blocks painted.
    pub acknowledged: bool,
    /// The selected manager arm, if any.
    pub arm: Option<ManagerArm>,
    /// Arm B's typed hex text (only meaningful when `arm == Some(ManagerArm::B)`).
    pub arm_b_hex: String,
    /// A bad hex parse's field-error sentence, cleared on the next successful parse attempt.
    pub arm_b_error: Option<String>,
    /// Index into [`CachedCreateInputs::cat_coins`] of the chosen reward-CAT coin.
    pub selected_coin: Option<usize>,
    /// The launch comment's root, as typed hex (paired with the store id to build a
    /// [`LaunchComment`]).
    pub root_hex: String,
    /// The epoch-length field's typed text, in seconds.
    pub epoch_seconds_text: String,
    /// The first-epoch-start field's typed text, in unix seconds.
    pub first_epoch_text: String,
    /// The network-fee field's typed text, in mojos.
    pub fee_text: String,
}

fn drafts() -> &'static Mutex<HashMap<String, CardDraft>> {
    static DRAFTS: std::sync::OnceLock<Mutex<HashMap<String, CardDraft>>> =
        std::sync::OnceLock::new();
    DRAFTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `store_id`'s current draft, or a fresh (empty) one -- paint-time, no I/O.
pub fn draft(store_id: &str) -> CardDraft {
    drafts()
        .lock()
        .unwrap()
        .get(store_id)
        .cloned()
        .unwrap_or_default()
}

/// Replaces `store_id`'s draft, as edited this frame -- the click/edit handlers' write side.
pub fn set_draft(store_id: &str, draft: CardDraft) {
    drafts().lock().unwrap().insert(store_id.to_string(), draft);
}

/// Drops `store_id`'s draft -- called once [`attempt_submit`] hands a job to the sink, or on an
/// explicit "start over".
pub fn clear_draft(store_id: &str) {
    drafts().lock().unwrap().remove(store_id);
}

/// The account-wide inputs the card's manager-choice, coin-picker and terms steps read, taken by
/// the pane's own refresh cadence (`dig-app.rs`, off the paint path) and cached here. `None` until
/// the first refresh completes.
#[derive(Debug, Clone, Default)]
pub struct CachedCreateInputs {
    /// This profile's wallet public key, for arm A -- `None` while locked or before the first
    /// refresh.
    pub manager_public_key: Option<PublicKey>,
    /// This profile's unspent, lineage-proven $DIG coins.
    pub cat_coins: Vec<Cat>,
    /// How many further $DIG candidates existed beyond what was listed.
    pub cat_omitted: usize,
    /// The account was locked when the listing was attempted.
    pub cat_locked: bool,
    /// Confirmed, unspent XCH coins at this profile's own puzzle hash, candidates for
    /// [`select_funding_coin`].
    pub xch_coins: Vec<Coin>,
}

fn cached_inputs_slot() -> &'static Mutex<Option<CachedCreateInputs>> {
    static SLOT: std::sync::OnceLock<Mutex<Option<CachedCreateInputs>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Records this cycle's refresh -- called ONLY by the pane's refresh cadence (`dig-app.rs`), never
/// from paint.
pub fn set_cached_inputs(inputs: CachedCreateInputs) {
    *cached_inputs_slot().lock().unwrap() = Some(inputs);
}

/// The last-cached inputs, paint-time, no I/O. `None` before the first refresh has completed.
pub fn cached_inputs() -> Option<CachedCreateInputs> {
    cached_inputs_slot().lock().unwrap().clone()
}

fn availability_slot() -> &'static Mutex<Option<DistributorMintAvailability>> {
    static SLOT: std::sync::OnceLock<Mutex<Option<DistributorMintAvailability>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Records this cycle's [`DistributorMintAvailability::probe`] answer -- called ONLY by the pane's
/// refresh cadence, never from paint (probing reads the chain).
pub fn set_cached_availability(availability: DistributorMintAvailability) {
    *availability_slot().lock().unwrap() = Some(availability);
}

/// The last-probed availability, paint-time, no I/O. `None` before the first probe has completed
/// (every card then paints "not checked yet", via [`super::pane::create_availability_sentence`]).
pub fn cached_availability() -> Option<DistributorMintAvailability> {
    *availability_slot().lock().unwrap()
}

/// One thing [`attempt_submit`] refused before ever reaching the sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptRefusal {
    /// The warning blocks have not been acknowledged yet.
    NotAcknowledged,
    /// No manager arm was chosen.
    NoManagerChoice,
    /// Arm B's hex text did not parse to exactly 32 bytes.
    BadManagerHash,
    /// No reward-CAT coin was chosen, or the index no longer resolves.
    NoRewardCoin,
    /// The root-hex text did not parse to exactly 32 bytes.
    BadRoot,
    /// The epoch length or first-epoch-start terms were refused (see [`TermsRefusal`]).
    Terms(TermsRefusal),
    /// The fee text did not parse as a plain integer.
    BadFee,
    /// No confirmed XCH coin covers the fee.
    NoFundingCoin,
    /// The create-sink worker is not installed (headless build, or a test).
    NoSink,
    /// The shared worker was already busy; see [`busy_sentence`].
    Busy,
}

/// Validates `draft` against `cached`, builds a [`RewardCreateJob`](super::create_sink::RewardCreateJob)
/// and hands it to [`super::create_sink::get`]. The card's own submit-button handler is the sole
/// intended caller.
///
/// On [`super::create_sink::Refused::Busy`], records [`busy_sentence`] via
/// [`record_submit_error`] (never silence -- this module's own doc comment) and leaves the draft
/// in place so the person can retry. On every other refusal, nothing is recorded here: paint shows
/// the refusal sentence for the returned [`AttemptRefusal`] directly, because none of them are the
/// worker's business.
pub fn attempt_submit(
    store_id: &str,
    draft: &CardDraft,
    cached: &CachedCreateInputs,
    store_id_bytes: Bytes32,
    now_unix_seconds: u64,
) -> Result<(), AttemptRefusal> {
    if !draft.acknowledged {
        return Err(AttemptRefusal::NotAcknowledged);
    }

    let choice = match draft.arm {
        Some(ManagerArm::A) => {
            let pk = cached
                .manager_public_key
                .ok_or(AttemptRefusal::NoManagerChoice)?;
            ManagerChoice::SingleKeyBuiltHere(pk)
        }
        Some(ManagerArm::B) => {
            let hash = parse_hash_hex(&draft.arm_b_hex).ok_or(AttemptRefusal::BadManagerHash)?;
            ManagerChoice::HashSuppliedByCaller(hash)
        }
        None => return Err(AttemptRefusal::NoManagerChoice),
    };

    let shown = WarningsShown::having_displayed(&REQUIRED_WARNING_KEYS)
        .expect("the card always paints exactly the five required warning keys");
    let acknowledged = CreationGate::unacknowledged().acknowledge(shown);
    let made = ManagerChoiceMade::for_choice(&choice);
    let launchable = acknowledged.with_manager_choice(made, choice);

    let reward_cat = draft
        .selected_coin
        .and_then(|i| cached.cat_coins.get(i))
        .copied()
        .ok_or(AttemptRefusal::NoRewardCoin)?;

    let root = parse_hash_hex(&draft.root_hex).ok_or(AttemptRefusal::BadRoot)?;
    let generation = LaunchComment::new(store_id_bytes, root);

    let distributor_epoch_seconds: u64 = draft
        .epoch_seconds_text
        .trim()
        .parse()
        .map_err(|_| AttemptRefusal::Terms(TermsRefusal::ZeroEpoch))?;
    let first_epoch_start: u64 = draft
        .first_epoch_text
        .trim()
        .parse()
        .map_err(|_| AttemptRefusal::Terms(TermsRefusal::FirstEpochInPast))?;
    validate_epoch_terms(
        distributor_epoch_seconds,
        first_epoch_start,
        now_unix_seconds,
    )
    .map_err(AttemptRefusal::Terms)?;

    let fee: u64 = draft
        .fee_text
        .trim()
        .parse()
        .map_err(|_| AttemptRefusal::BadFee)?;
    let funding =
        select_funding_coin(&cached.xch_coins, fee).ok_or(AttemptRefusal::NoFundingCoin)?;

    let terms = DistributorMintTerms {
        funding,
        reward_cat,
        distributor_epoch_seconds,
        first_epoch_start,
        generation,
        fee,
        now_unix_seconds,
    };

    let job = super::create_sink::RewardCreateJob {
        store_id: store_id.to_string(),
        launchable,
        terms,
    };

    let Some(sink) = super::create_sink::get() else {
        return Err(AttemptRefusal::NoSink);
    };
    match sink.submit(job) {
        Ok(()) => {
            clear_draft(store_id);
            Ok(())
        }
        Err(super::create_sink::Refused::Busy) => {
            record_submit_error(store_id, busy_sentence());
            Err(AttemptRefusal::Busy)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewards::mint::tests::{
        confirm_bundle, fixture_launchable, fixture_minter, fixture_terms, AcceptingPublisher,
    };
    use crate::rewards::mint::DistributorMint;
    use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;
    use dig_account::mint::MintNetwork;

    /// (c) A fixture door's `begin` -> the pane state holds the pending mint -> `status` on a mock
    /// chain drives Awaiting then Confirmed.
    #[test]
    fn submit_stores_the_pending_mint_and_status_drives_awaiting_then_confirmed() {
        let (_residency, minter) = fixture_minter();
        let now = 2_000_000_000;
        let (terms, chain) = fixture_terms(&minter, now);
        let publisher = AcceptingPublisher::default();
        let network = MintNetwork::mainnet();
        let manager_key = minter.public_key().expect("unlocked");

        let door = DistributorMint::new(&minter, network, &MAINNET_CONSTANTS, &chain, &publisher);
        let pending = submit(door, fixture_launchable(manager_key), terms).expect("mint begins");
        let launcher_id = pending.distributor_launcher_id();

        let store_id = "test-store-submit";
        record_submission(store_id, pending);
        assert!(has_pending(store_id));

        let awaiting = refresh_and_render(store_id, &chain).expect("slot exists");
        assert!(
            awaiting.contains("submitted to the mempool -- not yet on chain"),
            "Awaiting sentence must contain the required verbatim substring: {awaiting:?}"
        );
        assert!(
            awaiting.to_lowercase().contains("predicted"),
            "the predicted id sentence must contain the word \"predicted\": {awaiting:?}"
        );

        let confirmed_at = 20;
        let confirmed_chain = confirm_bundle(
            chain,
            &publisher.only_bundle(),
            launcher_id,
            confirmed_at,
            now,
        )
        .with_peak(confirmed_at + dig_account::mint::evidence::MIN_CONFIRMATION_DEPTH);

        let confirmed = refresh_and_render(store_id, &confirmed_chain).expect("slot exists");
        assert!(
            !confirmed.contains("could not read the chain"),
            "a confirmed read must not render as unknown: {confirmed:?}"
        );
    }

    /// `pending_store_ids` is the pane's refresh cadence's own enumeration -- the set it must call
    /// [`refresh_and_render`] for. Asserted with `contains`, not `==`: this crate's tests run in one
    /// process and share the same global slots, so another test's own store id may legitimately be
    /// present too.
    #[test]
    fn pending_store_ids_lists_a_freshly_submitted_store() {
        let (_residency, minter) = fixture_minter();
        let now = 2_000_000_000;
        let (terms, chain) = fixture_terms(&minter, now);
        let publisher = AcceptingPublisher::default();
        let network = MintNetwork::mainnet();
        let manager_key = minter.public_key().expect("unlocked");

        let door = DistributorMint::new(&minter, network, &MAINNET_CONSTANTS, &chain, &publisher);
        let pending = submit(door, fixture_launchable(manager_key), terms).expect("mint begins");

        let store_id = "test-store-enumeration";
        record_submission(store_id, pending);
        assert!(
            pending_store_ids().iter().any(|id| id == store_id),
            "a freshly recorded pending mint must appear in pending_store_ids()"
        );
    }

    /// (6) The submit-button handler's own logic: [`attempt_submit`] refuses before the sink is
    /// ever reached when the draft is incomplete, and rejects arm B's hex the same way
    /// [`parse_hash_hex`] rejects it everywhere else.
    #[test]
    fn attempt_submit_refuses_before_the_sink_on_an_incomplete_draft() {
        let cached = CachedCreateInputs::default();
        let draft = CardDraft::default();
        let store_id_bytes = Bytes32::from([9u8; 32]);

        assert_eq!(
            attempt_submit("incomplete", &draft, &cached, store_id_bytes, 0),
            Err(AttemptRefusal::NotAcknowledged)
        );

        let mut acked = draft.clone();
        acked.acknowledged = true;
        assert_eq!(
            attempt_submit("incomplete", &acked, &cached, store_id_bytes, 0),
            Err(AttemptRefusal::NoManagerChoice)
        );

        let mut bad_hash = acked.clone();
        bad_hash.arm = Some(ManagerArm::B);
        bad_hash.arm_b_hex = "not-hex".to_string();
        assert_eq!(
            attempt_submit("incomplete", &bad_hash, &cached, store_id_bytes, 0),
            Err(AttemptRefusal::BadManagerHash)
        );
    }

    /// (6) The happy path: a fully valid draft reaches [`super::create_sink::get`] and, once the
    /// worker runs the fixture door, the pending mint is recorded exactly as [`submit`] itself
    /// would record it -- and (Busy) the SAME draft, resubmitted while the shared flag is still
    /// held, is refused and renders [`busy_sentence`] via [`last_rendered`] rather than being
    /// silently dropped. This is the test that makes [`copy::CREATE_BUSY`] reachable outside test
    /// code: [`busy_sentence`]'s sole production caller is [`attempt_submit`], exercised here.
    #[test]
    fn attempt_submit_is_refused_busy_then_reaches_the_sink_and_records_pending() {
        let (_residency, minter) = fixture_minter();
        let now = 2_000_000_000;
        let (terms, chain) = fixture_terms(&minter, now);
        let manager_key = minter.public_key().expect("a fresh residency is unlocked");
        let listing = minter
            .dig_cat_coins(&chain)
            .expect("the fixture lineage resolves");

        let cached = CachedCreateInputs {
            manager_public_key: Some(manager_key),
            cat_coins: listing.into_cats(),
            cat_omitted: 0,
            cat_locked: false,
            xch_coins: vec![terms.funding],
        };

        let draft = CardDraft {
            acknowledged: true,
            arm: Some(ManagerArm::A),
            arm_b_hex: String::new(),
            arm_b_error: None,
            selected_coin: Some(0),
            root_hex: "09".repeat(32),
            epoch_seconds_text: terms.distributor_epoch_seconds.to_string(),
            first_epoch_text: terms.first_epoch_start.to_string(),
            fee_text: terms.fee.to_string(),
        };

        let store_id = "test-store-attempt-submit";
        let store_id_bytes = Bytes32::from([9u8; 32]);

        // The whole crate shares one process-wide sink slot (`create_sink::install`/`get`), so this
        // is the ONE test in the crate allowed to install it -- see this module's own tests for why
        // every other test builds a `RewardCreateSink` locally instead.
        let publisher = AcceptingPublisher::default();
        let shared_busy = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let sink = super::super::create_sink::RewardCreateSink::spawn(
            std::sync::Arc::clone(&shared_busy),
            move |job: super::super::create_sink::RewardCreateJob| {
                let door = DistributorMint::new(
                    &minter,
                    MintNetwork::mainnet(),
                    &MAINNET_CONSTANTS,
                    &chain,
                    &publisher,
                );
                match submit(door, job.launchable, job.terms) {
                    Ok(pending) => record_submission(&job.store_id, pending),
                    Err(message) => record_submit_error(&job.store_id, message),
                }
            },
        );
        super::super::create_sink::install(sink);

        assert_eq!(
            attempt_submit(store_id, &draft, &cached, store_id_bytes, now),
            Err(AttemptRefusal::Busy)
        );
        assert_eq!(
            last_rendered(store_id).as_deref(),
            Some(busy_sentence().as_str()),
            "a busy refusal must render CREATE_BUSY's own sentence"
        );

        shared_busy.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            attempt_submit(store_id, &draft, &cached, store_id_bytes, now),
            Ok(())
        );

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while !has_pending(store_id) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            has_pending(store_id),
            "the accepted job never ran, or never recorded the pending mint"
        );
    }

    /// (c) continued: a `status` read that errs leaves the pending state intact and renders the
    /// "unknown" sentence -- never failure, never success.
    #[test]
    fn a_status_read_error_keeps_the_pending_state_and_renders_unknown() {
        let (_residency, minter) = fixture_minter();
        let now = 2_000_000_000;
        let (terms, chain) = fixture_terms(&minter, now);
        let publisher = AcceptingPublisher::default();
        let network = MintNetwork::mainnet();
        let manager_key = minter.public_key().expect("unlocked");

        let door = DistributorMint::new(&minter, network, &MAINNET_CONSTANTS, &chain, &publisher);
        let pending = submit(door, fixture_launchable(manager_key), terms).expect("mint begins");

        let store_id = "test-store-error";
        record_submission(store_id, pending);

        let failing_chain = dig_chainsource_interface::MockChainSource::new().fail_with(
            dig_chainsource_interface::ChainSourceError::Transport("no peer".into()),
        );
        let rendered = refresh_and_render(store_id, &failing_chain).expect("slot exists");
        assert_eq!(rendered, copy::CREATE_STATUS_UNKNOWN.text());
        assert!(
            has_pending(store_id),
            "an errored status read must not drop the pending state"
        );
    }

    /// (a) Render-path scan: none of the manager-choice English or per-locale bodies contain a
    /// forbidden word.
    #[test]
    fn manager_choice_render_path_never_uses_a_forbidden_word() {
        for lang in crate::i18n::SUPPORTED {
            for msg in [
                copy::CREATE_MANAGER_ARM_A_LABEL,
                copy::CREATE_MANAGER_ARM_A_BODY,
                copy::CREATE_MANAGER_ARM_B_LABEL,
                copy::CREATE_MANAGER_ARM_B_BODY,
            ] {
                let text = msg.text_in(lang).to_lowercase();
                for word in FORBIDDEN_MANAGER_WORDS {
                    assert!(
                        !text.contains(word),
                        "{:?} ({}) contains forbidden word {word:?}: {text:?}",
                        msg.key(),
                        lang.tag()
                    );
                }
            }
        }
    }

    /// (b) No `rewards-create-*` body contains "created" except the Confirmed-adjacent one
    /// (`CREATE_AWAITING`, which also carries the Confirmed bridging sentence -- see
    /// `render_status`).
    #[test]
    fn no_create_card_body_contains_created_except_the_confirmed_arm() {
        for msg in [
            copy::CREATE_ACK_BUTTON,
            copy::CREATE_MANAGER_ARM_A_LABEL,
            copy::CREATE_MANAGER_ARM_A_BODY,
            copy::CREATE_MANAGER_ARM_B_LABEL,
            copy::CREATE_MANAGER_ARM_B_BODY,
            copy::CREATE_MANAGER_ARM_B_FIELD,
            copy::CREATE_COIN_ROW,
            copy::CREATE_COIN_OMITTED,
            copy::CREATE_COIN_LOCKED,
            copy::CREATE_COIN_EMPTY,
            copy::CREATE_TERMS_EPOCH_LABEL,
            copy::CREATE_TERMS_EPOCH_ZERO,
            copy::CREATE_TERMS_FIRST_EPOCH_LABEL,
            copy::CREATE_TERMS_FIRST_EPOCH_PAST,
            copy::CREATE_TERMS_FEE_LABEL,
            copy::CREATE_TERMS_NO_FUNDING_COIN,
            copy::CREATE_SUBMIT_BUTTON,
            copy::CREATE_SUBMIT_LOCKED,
            copy::CREATE_FAILED,
            copy::CREATE_STATUS_UNKNOWN,
        ] {
            let text = msg.text_in(crate::i18n::Language::En).to_lowercase();
            assert!(
                !text.contains("created"),
                "{:?} must not contain \"created\": {text:?}",
                msg.key()
            );
        }
    }

    #[test]
    fn zero_epoch_and_past_start_are_refused() {
        assert_eq!(
            validate_epoch_terms(0, 100, 50),
            Err(TermsRefusal::ZeroEpoch)
        );
        assert_eq!(
            validate_epoch_terms(604_800, 10, 50),
            Err(TermsRefusal::FirstEpochInPast)
        );
        assert_eq!(validate_epoch_terms(604_800, 100, 50), Ok(()));
    }

    #[test]
    fn funding_coin_prefers_the_smallest_that_covers() {
        use chia_protocol::{Bytes32, Coin};
        let small = Coin::new(Bytes32::from([1u8; 32]), Bytes32::from([9u8; 32]), 1_000);
        let exact = Coin::new(Bytes32::from([2u8; 32]), Bytes32::from([9u8; 32]), 2_000);
        let large = Coin::new(Bytes32::from([3u8; 32]), Bytes32::from([9u8; 32]), 5_000);
        let picked = select_funding_coin(&[small, large, exact], 2_000).unwrap();
        assert_eq!(picked.coin_id(), exact.coin_id());
    }

    #[test]
    fn funding_coin_falls_back_to_the_largest_when_none_covers() {
        use chia_protocol::{Bytes32, Coin};
        let small = Coin::new(Bytes32::from([1u8; 32]), Bytes32::from([9u8; 32]), 1_000);
        let large = Coin::new(Bytes32::from([3u8; 32]), Bytes32::from([9u8; 32]), 5_000);
        let picked = select_funding_coin(&[small, large], 10_000).unwrap();
        assert_eq!(picked.coin_id(), large.coin_id());
    }

    #[test]
    fn no_candidates_yields_none() {
        assert!(select_funding_coin(&[], 100).is_none());
    }
}

#[cfg(test)]
mod subject_tests {
    /// (d) `DistributorMintDoor::begin` has exactly one production caller outside `mint.rs`: this
    /// module's own [`super::submit`]. Comment-stripped, needle assembled with `format!` so this
    /// scan never self-matches its own source (this crate's established convention -- see
    /// `create.rs`'s `subject_tests`).
    #[test]
    fn begin_has_exactly_one_production_caller_outside_mint_rs() {
        let needle = format!("{}{}", ".beg", "in(");
        for (name, src) in [
            ("copy.rs", include_str!("copy.rs")),
            ("create.rs", include_str!("create.rs")),
            ("pane.rs", include_str!("pane.rs")),
            ("clawback.rs", include_str!("clawback.rs")),
        ] {
            let production = strip_test_and_comments(src);
            assert!(
                !production.contains(&needle),
                "{name} must not call `.begin(` -- only create_card::submit and mint.rs may"
            );
        }

        let create_card_production = strip_test_and_comments(include_str!("create_card.rs"));
        let call_count = create_card_production.matches(&needle).count();
        assert_eq!(
            call_count, 1,
            "create_card.rs's own production code must call `.begin(` exactly once (inside \
             `submit`), found {call_count}"
        );
    }

    fn strip_test_and_comments(src: &str) -> String {
        let production = src.split("#[cfg(test)]").next().unwrap_or(src);
        production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
