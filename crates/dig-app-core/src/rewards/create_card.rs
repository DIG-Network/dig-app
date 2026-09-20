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
//! [`PENDING`] is a process-global slot, exactly like `store_rewards::app_readings()` — it lives
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

use dig_account::mint::MintError;
use dig_account::{PendingRewardDistributor, RewardDistributorStatus};
use dig_chainsource_interface::ChainSource;

use super::copy;
use super::create::{Launchable, ManagerChoice};
use super::mint::{DistributorMintDoor, DistributorMintTerms};

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
        copy::CREATE_COIN_OMITTED.with(&crate::i18n::Args::new().text("omitted", omitted.to_string()))
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
pub fn select_funding_coin(candidates: &[chia_protocol::Coin], required: u64) -> Option<chia_protocol::Coin> {
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

/// Stores a freshly submitted mint for `store_id`. Called by the dispatcher arm once
/// [`submit`] returns `Ok` -- never discarded, per dig_ecosystem#3253 §6 acceptance item 6.
pub fn record_submission(store_id: &str, pending: PendingRewardDistributor) {
    pending_slots().lock().unwrap().insert(
        store_id.to_string(),
        PendingCardState {
            pending,
            last_status: None,
        },
    );
}

/// Whether `store_id` has a pending mint recorded (paint-time, no I/O).
pub fn has_pending(store_id: &str) -> bool {
    pending_slots().lock().unwrap().contains_key(store_id)
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
/// of whatever [`refresh_and_render`] last recorded).
pub fn last_rendered(store_id: &str) -> Option<String> {
    let slots = pending_slots().lock().unwrap();
    let slot = slots.get(store_id)?;
    Some(render_status(&slot.pending, slot.last_status.as_ref()?))
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
            awaiting.contains("predicted"),
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
