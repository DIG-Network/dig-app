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
//! `pending_slots()`, `submit_errors()`, the drafts map and the witness slot are process-global --
//! exactly like `store_rewards::app_readings()` -- and live for the process's lifetime ONLY. A
//! restart loses every in-flight pending mint's local record; the mint itself is not lost (it is
//! already pushed and confirmable from the chain), but this card's memory of having submitted it
//! is, so the card offers CREATE again for a store whose launch is still settling. That hole is
//! dig_ecosystem#3366; closing it needs a durable store, not this one.
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
use super::pane::{Acknowledged, CreationGate, WarningsShown};

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
/// Whether a create-sink worker is installed -- paint-time, no I/O. `false` in the headless build
/// and in the gallery, where the submit button must not be painted at all: a button whose press
/// can only ever be refused is a dead control.
pub fn sink_installed() -> bool {
    super::create_sink::get().is_some()
}

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

/// One store's in-progress create card, holding ONLY raw user input -- text the person typed and
/// which radio row is lit. It carries no evidence of anything and grants nothing: how far the card
/// has walked the acknowledgement ladder lives in `CardWitnesses`, a separate, private,
/// un-clonable slot, because a `Clone + Default` struct with all-public fields is a value any
/// module can conjure whole.
///
/// # Why the ladder is NOT a pair of booleans here (dig-app#413 adversarial F1)
///
/// An earlier revision held `acknowledged: bool` and `manager_committed: bool` on this struct and
/// re-minted [`WarningsShown`]/[`Acknowledged`]/[`ManagerChoiceMade`] from the constant
/// [`super::pane::REQUIRED_WARNING_KEYS`] inside [`attempt_submit`] whenever those booleans were
/// true. That made the whole typed ladder ceremony: `set_draft("s", CardDraft { acknowledged:
/// true, .. })` -- one line, compiling from any module -- put a card on the sign-and-submit step
/// with no warning ever displayed. The witnesses now travel by value from the frame that painted
/// the blocks to the submit that consumes them, and no production code mints one from the
/// constant.
#[derive(Debug, Clone, Default)]
pub struct CardDraft {
    /// The selected manager arm, if any -- which radio row is lit, not a commitment. The
    /// commitment is [`commit_manager_choice`], which mints a witness.
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

/// Drops `store_id`'s draft AND every witness it had earned -- called once [`attempt_submit`]
/// hands a job to the sink, or on an explicit "start over". Starting over re-walks the ladder.
pub fn clear_draft(store_id: &str) {
    drafts().lock().unwrap().remove(store_id);
    witnesses().lock().unwrap().remove(store_id);
}

// ---------------------------------------------------------------------------------------------
// The witness slot -- the typed evidence one store's card has earned, held BY VALUE.
//
// Nothing here is `Clone`, `Copy` or constructible from outside, and no accessor hands a witness
// back out: paint learns only which STEP to draw (`ladder_stage`), and the witnesses leave exactly
// once, into a `Launchable`, through the private `take_launchable`.
// ---------------------------------------------------------------------------------------------

/// The typed evidence `store_id`'s card has earned so far. Private, un-clonable and only ever
/// mutated through [`record_acknowledgement`], [`commit_manager_choice`] and `take_launchable`.
#[derive(Debug, Default)]
struct CardWitnesses {
    /// Proof the five warning blocks were on screen and the person clicked past them -- minted
    /// only from the keys a frame actually painted.
    acknowledged: Option<Acknowledged>,
    /// The committed manager arm and the witness bound to that exact value. Held as a pair
    /// because `Acknowledged::with_manager_choice` needs both, and [`ManagerChoice`] is not
    /// `Clone`: the slot owns it and gives it up once.
    manager: Option<(ManagerChoiceMade, ManagerChoice)>,
}

fn witnesses() -> &'static Mutex<HashMap<String, CardWitnesses>> {
    static WITNESSES: std::sync::OnceLock<Mutex<HashMap<String, CardWitnesses>>> =
        std::sync::OnceLock::new();
    WITNESSES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Which step of the create card `store_id` has reached -- the ONLY thing the witness slot tells
/// paint. A stage is a `Copy` fact about the slot, not a capability: holding
/// [`LadderStage::Terms`] lets a caller draw the terms step, never submit one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LadderStage {
    /// Nothing acknowledged yet -- the warning blocks are the step.
    Warnings,
    /// The warnings are acknowledged; no manager arm is committed.
    Manager,
    /// Both witnesses are held; the terms and the submit control are the step.
    Terms,
}

/// How far `store_id`'s card has walked the ladder (paint-time, no I/O).
pub fn ladder_stage(store_id: &str) -> LadderStage {
    let held = witnesses().lock().unwrap();
    match held.get(store_id) {
        Some(CardWitnesses {
            acknowledged: Some(_),
            manager: Some(_),
        }) => LadderStage::Terms,
        Some(CardWitnesses {
            acknowledged: Some(_),
            manager: None,
        }) => LadderStage::Manager,
        _ => LadderStage::Warnings,
    }
}

/// Records that `store_id`'s warning blocks were displayed and acknowledged, evidenced by `shown`.
///
/// `shown` is taken BY VALUE and [`WarningsShown`] is neither `Copy` nor `Clone`, so the caller
/// must have obtained one from `WarningsShown::having_displayed` over the keys its own frame
/// really painted -- which is why the paint's `if let Some(shown) = shown` IS the acknowledgement
/// guard, rather than a boolean a later edit could set by hand.
pub fn record_acknowledgement(store_id: &str, shown: WarningsShown) {
    witnesses()
        .lock()
        .unwrap()
        .entry(store_id.to_string())
        .or_default()
        .acknowledged = Some(CreationGate::unacknowledged().acknowledge(shown));
}

/// Commits `choice` as `store_id`'s manager arm, minting the [`ManagerChoiceMade`] witness bound
/// to that exact value. Answers whether it was recorded.
///
/// Refuses on a card that has not acknowledged its warnings: the ladder is walked in order or not
/// at all, so a manager choice can never be the first rung.
pub fn commit_manager_choice(store_id: &str, choice: ManagerChoice) -> bool {
    let mut held = witnesses().lock().unwrap();
    let Some(entry) = held.get_mut(store_id) else {
        return false;
    };
    if entry.acknowledged.is_none() {
        return false;
    }
    entry.manager = Some((ManagerChoiceMade::for_choice(&choice), choice));
    true
}

/// Consumes BOTH of `store_id`'s witnesses and spends them on the one [`Launchable`] they can
/// make, or answers `None` and leaves the slot untouched when either is missing.
///
/// Taking is the point: once a job carries the `Launchable`, the card's slot is empty, so a
/// refused or dropped job leaves the person re-walking the ladder rather than re-submitting on
/// evidence that has already been spent.
fn take_launchable(store_id: &str) -> Option<Launchable> {
    let mut held = witnesses().lock().unwrap();
    let entry = held.entry(store_id.to_string()).or_default();
    match std::mem::take(entry) {
        CardWitnesses {
            acknowledged: Some(acknowledged),
            manager: Some((made, choice)),
        } => Some(acknowledged.with_manager_choice(made, choice)),
        partial => {
            *entry = partial;
            None
        }
    }
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

/// Caches the answer for an account nobody has unlocked: no mint is possible and no coin listing
/// exists. Called by the refresh cadence when there is no live session -- never left to the
/// previous unlock's cached coins, which would let a card be filled in against money the app can
/// no longer see.
///
/// The cadence is the binary's (`dig-app.rs`, every ten seconds); the READS are this crate's --
/// `DistributorMintAvailability::probe`, `RewardDistributorMinter::dig_cat_coins` and a
/// [`ChainSource`] coin-record query, all of which need traits the binary does not depend on. A
/// binary is also a test-free zone here, so the decisions about what a failed read MEANS belong on
/// this side of the boundary where they can be tested.
///
/// # Locked caches LOCKED
///
/// Every path that cannot see the wallet caches an empty, `cat_locked` listing rather than leaving
/// the previous unlock's coins in place: a card filled in against money the app can no longer see
/// is a spend proposed on stale evidence.
pub fn cache_locked() {
    set_cached_availability(DistributorMintAvailability::Locked);
    set_cached_inputs(CachedCreateInputs {
        cat_locked: true,
        ..CachedCreateInputs::default()
    });
}

/// Takes every input the card's paint needs and caches it, in one call, off the paint path.
///
/// # Why this lives here and not in the binary that calls it
///
/// The cadence is the binary's (`dig-app.rs`, every ten seconds); the READS are this crate's --
/// `DistributorMintAvailability::probe`, the minter's own `dig_cat_coins` and a [`ChainSource`]
/// coin-record query, all of which need traits the binary does not depend on. A binary is also a
/// test-free zone here, so the decisions about what a failed read MEANS belong on this side of the
/// boundary, where they can be tested.
///
/// # Locked caches LOCKED
///
/// Every path that cannot see the wallet caches an empty, `cat_locked` listing rather than leaving
/// the previous unlock's coins in place.
pub fn refresh_cached_inputs<C>(residency: &crate::account::residency::AccountResidency, chain: &C)
where
    C: ChainSource + ?Sized,
{
    set_cached_availability(DistributorMintAvailability::probe(residency, chain));

    let Some(minter) = residency.reward_distributor_minter() else {
        set_cached_inputs(CachedCreateInputs {
            cat_locked: true,
            ..CachedCreateInputs::default()
        });
        return;
    };

    let (cat_coins, cat_omitted, cat_locked) = match minter.dig_cat_coins(chain) {
        Ok(listing) => (listing.cats().to_vec(), listing.omitted(), false),
        // A listing this account cannot take is either a lock or a chain fault, and the two are
        // different sentences on the card -- `public_key()` answers which, because it fails for
        // exactly one of them.
        Err(_) => (Vec::new(), 0, minter.public_key().is_err()),
    };

    let xch_coins = minter
        .puzzle_hash()
        .ok()
        .and_then(|puzzle_hash| chain.coin_records_by_puzzle_hash(puzzle_hash, false).ok())
        .map(|records| {
            records
                .into_iter()
                .filter(|record| record.confirmed_height.is_some() && record.spent_height.is_none())
                .map(|record| record.coin)
                .collect()
        })
        .unwrap_or_default();

    set_cached_inputs(CachedCreateInputs {
        manager_public_key: minter.public_key().ok(),
        cat_coins,
        cat_omitted,
        cat_locked,
        xch_coins,
    });
}

/// One thing [`attempt_submit`] refused before ever reaching the sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptRefusal {
    /// The warning blocks have not been acknowledged yet.
    NotAcknowledged,
    /// No manager arm was chosen.
    NoManagerChoice,
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
/// [`record_submit_error`] (never silence -- this module's own doc comment). The typed draft
/// survives, but the WITNESSES do not: they were spent on the [`Launchable`] the dropped job
/// carried, so the person re-acknowledges rather than retrying on evidence already consumed. On
/// every other refusal, nothing is recorded here and the ladder is untouched: paint shows the
/// refusal sentence for the returned [`AttemptRefusal`] directly, because none of them are the
/// worker's business.
pub fn attempt_submit(
    store_id: &str,
    draft: &CardDraft,
    cached: &CachedCreateInputs,
    store_id_bytes: Bytes32,
    now_unix_seconds: u64,
) -> Result<(), AttemptRefusal> {
    // The stage is read BEFORE anything is validated so the two ladder refusals stay the first
    // two, and read WITHOUT taking: a typo in the fee must not cost the person their warnings.
    match ladder_stage(store_id) {
        LadderStage::Warnings => return Err(AttemptRefusal::NotAcknowledged),
        LadderStage::Manager => return Err(AttemptRefusal::NoManagerChoice),
        LadderStage::Terms => {}
    }

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

    // Last, and only once everything else is settled: the witnesses leave the card's slot. A
    // refusal above this line leaves the ladder intact; from here on the evidence is spent, which
    // is what makes a dropped or refused job cost a re-acknowledgement rather than nothing.
    let Some(sink) = super::create_sink::get() else {
        return Err(AttemptRefusal::NoSink);
    };
    let Some(launchable) = take_launchable(store_id) else {
        return Err(AttemptRefusal::NotAcknowledged);
    };

    let job = super::create_sink::RewardCreateJob {
        store_id: store_id.to_string(),
        launchable,
        terms,
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

// ---------------------------------------------------------------------------------------------
// The warnings step's rendered blocks (dig_ecosystem#3253 Q1). Every one of them is
// `super::copy`'s ratified constant, rendered verbatim -- the paint function in
// `confirm::gui::window::pane::store_rewards` names these accessors and nothing else, so the
// keys cannot drift apart from what is displayed.
// ---------------------------------------------------------------------------------------------

/// The warnings step's heading.
pub fn warning_heading() -> String {
    copy::WARNING_HEADING.text()
}

/// Warning block 1 -- payout does not need this computer.
pub fn warning_block_1() -> String {
    copy::WARNING_BLOCK_1.text()
}

/// Warning block 2 -- what a stopped prover freezes.
pub fn warning_block_2() -> String {
    copy::WARNING_BLOCK_2.text()
}

/// Warning block 3 -- no $DIG is lost, and what a clawback returns.
pub fn warning_block_3() -> String {
    copy::WARNING_BLOCK_3.text()
}

/// Warning block 4 -- the size of the exposure, AS A NUMBER, or `None` when this build cannot
/// state that number truthfully yet.
///
/// # Why this one is fallible and the other four are not
///
/// The ratified sentence names four figures. Three of them are measured here: `committed_amount`
/// is the WHOLE chosen reward-CAT coin (that is exactly what a launch does with it -- see
/// [`DistributorMintTerms::reward_cat`](super::mint::DistributorMintTerms)), and `committed_days`
/// / `epoch_days` both come from the typed epoch length. The fourth, `committed_epochs`, is `1`:
/// a launch creates exactly ONE reward slot (`dig_rewards_coin::launch`'s
/// `first_distributor_epoch_slot`) and commits nothing beyond it -- multi-epoch commitment is
/// `dig_rewards_coin::fund::commit_incentives_for_distributor_epoch`, the refill flow, which this
/// build does not ship (dig_ecosystem#3357).
///
/// `None` when no reward coin has been chosen or the epoch length has not been typed as a
/// positive integer: the block would then have to invent the numbers it quantifies, and the
/// warnings gate ([`super::pane::WarningsShown::having_displayed`]) refuses an acknowledgement
/// built on four blocks, which is what keeps an un-quantified warning from being acknowledged.
pub fn warning_block_4(reserve_base_units: u64, epoch_seconds: u64) -> Option<String> {
    if epoch_seconds == 0 {
        return None;
    }
    let committed_amount =
        crate::amount::format_asset_amount(crate::wallet::state::Asset::DIG, reserve_base_units)?;
    let epoch_days = epoch_seconds as f64 / 86_400.0;
    let days = format!("{epoch_days:.2}");
    Some(
        copy::WARNING_BLOCK_4.with(
            &crate::i18n::Args::new()
                .text("committed_epochs", "1")
                .text("committed_amount", committed_amount)
                .text("committed_days", days.clone())
                .text("epoch_days", days),
        ),
    )
}

/// Warning block 5 -- the manager key is the one thing that can never be undone.
pub fn warning_block_5() -> String {
    copy::WARNING_BLOCK_5.text()
}

/// The warnings step's closing line.
pub fn warning_closing() -> String {
    copy::WARNING_CLOSING.text()
}

/// The label of the control that commits the manager choice and moves to the terms step.
pub fn continue_button_label() -> String {
    copy::CREATE_CONTINUE.text()
}

impl AttemptRefusal {
    /// The sentence paint shows for this refusal, or `None` when the refusal is already visible as
    /// an unfilled field on the step the person is looking at.
    ///
    /// A refusal invents no new copy. The four that HAVE a sentence are the four a filled-looking
    /// form can still hit -- bad terms, no funding coin, a busy worker, no worker at all -- and
    /// the rest (`NotAcknowledged`, `NoManagerChoice`, `NoRewardCoin`,
    /// `BadRoot`, `BadFee`) are states the step itself already shows, where a second sentence
    /// would say what the empty field beside it says.
    pub fn sentence(&self) -> Option<String> {
        match self {
            AttemptRefusal::Terms(refusal) => Some(refusal.sentence()),
            AttemptRefusal::NoFundingCoin => Some(copy::CREATE_TERMS_NO_FUNDING_COIN.text()),
            AttemptRefusal::Busy | AttemptRefusal::NoSink => Some(busy_sentence()),
            _ => None,
        }
    }
}

/// The store-root field's label -- the root this distributor is launched against, which goes into
/// the [`LaunchComment`] beside the store id.
pub fn terms_root_label() -> String {
    copy::CREATE_TERMS_ROOT_LABEL.text()
}

/// The store-root field's help line -- which root is the right one, and what a wrong one costs.
pub fn terms_root_help() -> String {
    copy::CREATE_TERMS_ROOT_HELP.text()
}

/// Arm B's field-level refusal sentence for a hash that is not 32 bytes of hex.
pub fn manager_arm_b_error() -> String {
    copy::CREATE_MANAGER_ARM_B_ERROR.text()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A witness a TEST is allowed to mint from the constant, standing in for the frame that
    /// would have painted the five blocks. Production code may not do this -- that is exactly what
    /// [`the_warning_witness_is_never_minted_from_the_constant`] asserts -- and this helper lives
    /// below the `#[cfg(test)]` split so the scan does not see it.
    fn painted_five_keys() -> WarningsShown {
        WarningsShown::having_displayed(&crate::rewards::pane::REQUIRED_WARNING_KEYS)
            .expect("the five required keys are the five required keys")
    }

    /// Walks `store_id` up the whole ladder, as the paint code does across three frames.
    fn walk_the_ladder(store_id: &str, choice: ManagerChoice) {
        record_acknowledgement(store_id, painted_five_keys());
        assert!(
            commit_manager_choice(store_id, choice),
            "an acknowledged card must accept a manager choice"
        );
    }

    /// A draft cannot reach the submit seam without BOTH witnesses, and the witnesses cannot be
    /// conjured from the draft: the ladder's rungs are values held in the card's own slot.
    ///
    /// Each stage is asserted through [`attempt_submit`]'s refusal, which is read BEFORE any input
    /// is validated -- so this test is about the ladder, not about the terms.
    #[test]
    fn a_draft_cannot_reach_submit_without_an_acknowledgement_and_a_manager_choice() {
        let cached = CachedCreateInputs::default();
        let store = Bytes32::new([7u8; 32]);
        let store_id = "gate-test";
        clear_draft(store_id);

        let blank = CardDraft::default();
        assert_eq!(ladder_stage(store_id), LadderStage::Warnings);
        assert_eq!(
            attempt_submit(store_id, &blank, &cached, store, 1_000),
            Err(AttemptRefusal::NotAcknowledged)
        );

        // A manager choice is refused outright while the warnings are unacknowledged -- the rung
        // below it does not exist yet.
        assert!(
            !commit_manager_choice(store_id, ManagerChoice::HashSuppliedByCaller(store)),
            "a manager choice must not be the first rung of the ladder"
        );

        record_acknowledgement(store_id, painted_five_keys());
        assert_eq!(ladder_stage(store_id), LadderStage::Manager);
        assert_eq!(
            attempt_submit(store_id, &blank, &cached, store, 1_000),
            Err(AttemptRefusal::NoManagerChoice)
        );

        assert!(commit_manager_choice(
            store_id,
            ManagerChoice::HashSuppliedByCaller(store)
        ));
        assert_eq!(ladder_stage(store_id), LadderStage::Terms);
        // Past the ladder, and refused on the INPUTS instead -- no coin was chosen. The witnesses
        // survive a refusal that is not the sink's.
        assert_eq!(
            attempt_submit(store_id, &blank, &cached, store, 1_000),
            Err(AttemptRefusal::NoRewardCoin)
        );
        assert_eq!(ladder_stage(store_id), LadderStage::Terms);

        clear_draft(store_id);
        assert_eq!(
            ladder_stage(store_id),
            LadderStage::Warnings,
            "starting over drops the witnesses, so the ladder is walked again"
        );
    }

    /// Warning block 4 states figures or it does not paint -- it never invents one.
    #[test]
    fn warning_block_4_refuses_to_quantify_what_it_was_not_given() {
        assert_eq!(warning_block_4(1_000, 0), None);

        let painted = warning_block_4(1_000, 604_800).expect("a chosen coin and an epoch length");
        // Asserted by PLACEABLE NAME rather than by brace character: an unmatched brace in a
        // string or char literal in this file is exactly what makes `copy.rs`'s brace-walking
        // test-module stripper read the whole module as unbalanced.
        assert!(
            !painted.contains("committed_epochs"),
            "every placeable must be filled: {painted:?}"
        );
    }
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

        record_acknowledgement("incomplete", painted_five_keys());
        assert_eq!(
            attempt_submit("incomplete", &draft, &cached, store_id_bytes, 0),
            Err(AttemptRefusal::NoManagerChoice)
        );

        // Arm B's hex never reaches here: `commit_manager_choice` takes a parsed `ManagerChoice`,
        // so an unparseable hash cannot become a committed arm in the first place.
        assert!(parse_hash_hex("not-hex").is_none());
        clear_draft("incomplete");
    }

    /// (F1) The submit seam refuses a card whose ladder is unwalked BEFORE a sink is consulted and
    /// without a [`Launchable`] ever existing -- with a sink installed by this crate's one
    /// sink-installing test, the refusal is still the ladder's, never `NoSink` and never `Busy`.
    ///
    /// Deleting the `ladder_stage` match at the head of [`attempt_submit`] turns this RED.
    #[test]
    fn an_unwalked_ladder_is_refused_before_the_sink() {
        let cached = CachedCreateInputs::default();
        let store_id = "ladder-before-sink";
        clear_draft(store_id);
        assert_eq!(
            attempt_submit(
                store_id,
                &CardDraft::default(),
                &cached,
                Bytes32::from([3u8; 32]),
                0
            ),
            Err(AttemptRefusal::NotAcknowledged)
        );
        assert_eq!(ladder_stage(store_id), LadderStage::Warnings);
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

        walk_the_ladder(store_id, ManagerChoice::SingleKeyBuiltHere(manager_key));
        assert_eq!(
            attempt_submit(store_id, &draft, &cached, store_id_bytes, now),
            Err(AttemptRefusal::Busy)
        );
        assert_eq!(
            last_rendered(store_id).as_deref(),
            Some(busy_sentence().as_str()),
            "a busy refusal must render CREATE_BUSY's own sentence"
        );
        // (F1) The busy job was DROPPED, and it took the witnesses with it: the person re-walks
        // the ladder rather than re-submitting on evidence already spent. Removing the
        // `take_launchable` call from `attempt_submit` turns this assertion RED.
        assert_eq!(
            ladder_stage(store_id),
            LadderStage::Warnings,
            "a dropped job must spend the witnesses it carried"
        );
        assert_eq!(
            attempt_submit(store_id, &draft, &cached, store_id_bytes, now),
            Err(AttemptRefusal::NotAcknowledged),
            "and a retry before re-acknowledging is refused at the ladder"
        );

        shared_busy.store(false, std::sync::atomic::Ordering::SeqCst);
        walk_the_ladder(store_id, ManagerChoice::SingleKeyBuiltHere(manager_key));
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
    /// Every `.rs` file under this repo's `crates/` directory (all three packages -- `dig-app`,
    /// `dig-app-core`, `diga`), walked from the filesystem at TEST TIME rather than `include_str!`
    /// -- the file set is not known until the walk runs, and a fixed list (dig_ecosystem#3367's
    /// per-file predecessor) silently stops covering a file the moment a new one is added anywhere
    /// in the workspace. `target/` is skipped -- build output, never source.
    ///
    /// A scan that silently walked zero files would pass every "not found elsewhere" assertion
    /// below for the worst possible reason -- the vacuity assert makes that failure loud instead
    /// of a false green.
    fn workspace_rust_sources() -> Vec<(String, String)> {
        let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("dig-app-core sits directly under crates/")
            .to_path_buf();
        let mut files = Vec::new();
        collect_rust_files(&crates_dir, &mut files);
        assert!(
            files.len() > 20,
            "workspace_rust_sources walked only {} files under {} -- the walk is broken, not the \
             codebase",
            files.len(),
            crates_dir.display()
        );
        files
    }

    fn collect_rust_files(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                    continue;
                }
                collect_rust_files(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                if let Ok(src) = std::fs::read_to_string(&path) {
                    out.push((path.display().to_string(), src));
                }
            }
        }
    }

    /// (d) `DistributorMintDoor::begin` has exactly one production caller outside `mint.rs`: this
    /// module's own [`super::submit`]. Comment-stripped, needle assembled with `format!` so this
    /// scan never self-matches its own source (this crate's established convention -- see
    /// `create.rs`'s `subject_tests`).
    ///
    /// Widened crate-wide (dig_ecosystem#3367) from a hardcoded four-file list: any `.rs` file
    /// anywhere under `crates/` -- in ANY of the three packages here, not just this one -- is now
    /// checked, not just the four this module's own siblings happened to be at the time the
    /// original scan was written.
    ///
    /// `.begin(` is not a unique spelling: `Ceremony::begin`, the wallet slot-holders'
    /// `self.begin()`, `Feed::begin`, and `settings::probe`'s ladder `begin` all share it with
    /// `DistributorMintDoor::begin`, discovered enumerating every production `.begin(` call the
    /// moment this scan went crate-wide (dig_ecosystem#3367). Rather than loosen the needle --
    /// which would also stop catching a real second `DistributorMintDoor::begin` caller spelled
    /// the same generic way, since the trait is invoked through a generic `D: DistributorMintDoor`
    /// bound and never named at the call site at all -- every unrelated call found by this scan's
    /// own widening is excused by NAME below, each verified still present so a stale entry here
    /// fails loudly instead of silently widening the exemption.
    #[test]
    fn begin_has_exactly_one_production_caller_outside_mint_rs() {
        let needle = format!("{}{}", ".beg", "in(");
        const KNOWN_UNRELATED_CALLS: &[(&str, &str)] = &[
            ("src/bin/dig-app.rs", "Feed::app().begin(base.clone())"),
            ("src/account/profile_creation.rs", "ceremony.begin(seed)"),
            (
                "src/confirm/gui/window/pane/settings/probe.rs",
                "self.begin(configured)",
            ),
            (
                "src/profile_edit/commit.rs",
                "feed.begin(opening.clone())",
            ),
            ("src/profile_melt/mod.rs", "feed.begin(opening)"),
            ("src/transaction/mod.rs", "drop(self.begin(transaction))"),
            ("src/wallet/cancelling.rs", "if !self.begin()"),
            (
                "src/wallet/cancelling.rs",
                "Feed::app().begin(opening.clone())",
            ),
            ("src/wallet/making.rs", "if !self.begin()"),
            ("src/wallet/sending.rs", "if !self.begin()"),
            ("src/wallet/taking.rs", "if !self.begin()"),
            (
                "src/wallet/taking.rs",
                "Feed::app().begin(opening.clone())",
            ),
        ];

        for (path, src) in workspace_rust_sources() {
            let normalized_path = path.replace('\\', "/");
            if normalized_path.ends_with("create_card.rs")
                || normalized_path.ends_with("mint.rs")
                // An integration-test crate under a package's `tests/` directory carries no
                // `#[cfg(test)]` marker of its own (the whole file IS the test crate), so
                // `strip_test_and_comments` cannot cut it -- its every line would otherwise read
                // as production.
                || normalized_path.contains("/tests/")
            {
                continue;
            }
            let production = strip_test_and_comments(&src);
            let mut remaining = production;
            for (exception_path, exception_call) in KNOWN_UNRELATED_CALLS {
                if normalized_path.ends_with(exception_path) {
                    assert!(
                        remaining.contains(exception_call),
                        "{path}'s known-unrelated `.begin(` exception {exception_call:?} is no \
                         longer present -- update or remove this exception, do not leave a stale \
                         exemption"
                    );
                    remaining = remaining.replacen(exception_call, "", 1);
                }
            }
            assert!(
                !remaining.contains(&needle),
                "{path} must not call `.begin(` -- only create_card::submit and mint.rs may"
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

    /// `attempt_submit` has exactly one production caller crate-wide: the submit button's click
    /// handler in `store_rewards.rs`'s paint code (dig_ecosystem#3367) -- a second call site would
    /// be a second, unwitnessed way to reach the sink `attempt_submit` guards. Same device as
    /// [`begin_has_exactly_one_production_caller_outside_mint_rs`] above: crate-wide walk, needle
    /// assembled with `format!` so this scan never self-matches its own source.
    #[test]
    fn attempt_submit_has_exactly_one_production_caller() {
        let needle = format!("{}{}", "attempt_sub", "mit(");
        for (path, src) in workspace_rust_sources() {
            let normalized_path = path.replace('\\', "/");
            if normalized_path.ends_with("create_card.rs")
                || normalized_path.ends_with("store_rewards.rs")
                || normalized_path.contains("/tests/")
            {
                continue;
            }
            let production = strip_test_and_comments(&src);
            assert!(
                !production.contains(&needle),
                "{path} must not call `attempt_submit(` -- only store_rewards.rs's paint code may"
            );
        }

        let paint = paint_production();
        let call_count = paint.matches(&needle).count();
        assert_eq!(
            call_count, 1,
            "store_rewards.rs's paint code must call `attempt_submit(` exactly once, found \
             {call_count}"
        );
    }

    /// (F1) No production code re-mints the warning witness from the constant.
    ///
    /// `WarningsShown::having_displayed(&REQUIRED_WARNING_KEYS)` typechecks from anywhere, so the
    /// ONE thing that keeps the ladder honest is that no shipping code does it: the witness must
    /// come from the keys a frame really painted. `create_card.rs` may not name the constant at
    /// all; `store_rewards.rs` names it only to LABEL the blocks it is placing, and must never
    /// hand the whole array to the constructor.
    ///
    /// Needles are assembled with `format!` so this scan never matches its own source.
    #[test]
    fn the_warning_witness_is_never_minted_from_the_constant() {
        let constant = format!("{}{}", "REQUIRED_WARNING", "_KEYS");
        let forge = format!("{}{}{}", "having_displayed(&", "REQUIRED_WARNING", "_KEYS");

        let create_card = strip_test_and_comments(include_str!("create_card.rs"));
        assert!(
            !create_card.contains(&constant),
            "create_card.rs production code must not name the warning-key constant at all"
        );

        let paint = paint_production();
        assert!(
            !paint.contains(&forge),
            "store_rewards.rs must build the witness from the keys it painted, never from the \
             constant"
        );
        assert!(
            paint.contains(&constant),
            "store_rewards.rs is expected to name the constant to label its blocks -- if it no \
             longer does, this guard is scanning the wrong file"
        );
    }

    /// (F1) The acknowledgement is recorded ONLY under the painted-keys witness, and the ack
    /// button is enabled only when that witness exists.
    ///
    /// Removing either the `if let Some(shown) = shown` binding or the `shown.is_some()` on the
    /// button's `enabled` turns this RED. The binding is also the type's own guard --
    /// `record_acknowledgement` takes a `WarningsShown` by value -- so deleting it does not
    /// compile either; this test is what makes the BUTTON's half checkable.
    #[test]
    fn the_acknowledgement_is_recorded_only_under_the_painted_keys_witness() {
        let paint = paint_production();
        let record = format!("{}{}", "record_acknowledge", "ment(store_id, shown)");
        let bind = format!("{}{}", "if let Some(shown) = ", "shown");
        let enabled = format!("{}{}", "live && ", "shown.is_some()");

        assert_eq!(
            paint.matches(&record).count(),
            1,
            "exactly one production call records an acknowledgement"
        );
        assert!(
            paint.contains(&bind),
            "the acknowledgement must be recorded under the painted-keys witness binding"
        );
        assert!(
            paint.contains(&enabled),
            "the ack button must be enabled only when the painted keys produced a witness"
        );
        let guarded = paint
            .split(&bind)
            .nth(1)
            .expect("the witness binding exists");
        assert!(
            guarded.contains(&record),
            "the acknowledgement call must sit INSIDE the witness binding"
        );
    }

    /// `store_rewards.rs`'s production text.
    ///
    /// Cut at the test-module DECLARATION, not at the first `#[cfg(test)]`: that module is
    /// `#[path = "store_rewards_tests.rs"] mod tests;` with no body, and the file's first
    /// `#[cfg(test)]` is a small lock helper hundreds of lines ABOVE the paint code -- cutting
    /// there would throw the whole card away and pass every scan for the worst possible reason.
    /// Same device as `copy.rs`'s `every_create_card_accessor_is_named_by_the_paint_code`.
    fn paint_production() -> String {
        let src = include_str!("../confirm/gui/window/pane/store_rewards.rs")
            .split("#[path = \"store_rewards_tests.rs\"]")
            .next()
            .expect("store_rewards.rs always declares its sibling test module");
        let production: String = src
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            production.contains("fn create_card_steps"),
            "the cut removed the paint code itself -- every scan over it would pass vacuously"
        );
        production
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
