//! Every sentence this pane shows a person, as `Msg` keys into [`crate::i18n`]'s existing fluent
//! catalogs — dig-app already has an i18n layer; this module follows it rather than inventing a
//! second one.
//!
//! # Copy contract
//!
//! Every English value below is copied VERBATIM from `DECISIONS-3253.md` (ratified,
//! loop-decider + epic owner). Do not reword, summarize or "improve" a sentence here — if a
//! sentence does not fit a layout, the layout changes, never the sentence. The non-English catalog
//! entries are provisional/machine-quality placeholders (a genuine, if simplistic, per-locale
//! translation, never an English copy — see `i18n::tests::a_locale_is_not_english_in_disguise`);
//! they are not this lane's to finalize either, the same way the pre-DECISIONS English was not.

use crate::i18n::Msg;

// ---------------------------------------------------------------------------------------------
// Q1 — the creation-time uptime warning. Five blocks + heading + closing line, all visible at
// once (DECISIONS-3253 rendering rule 1); no key here may be truncated, collapsed or paginated.
// ---------------------------------------------------------------------------------------------

pub const WARNING_HEADING: Msg = Msg::new("rewards-warning-heading");
pub const WARNING_BLOCK_1: Msg = Msg::new("rewards-warning-block-1");
pub const WARNING_BLOCK_2: Msg = Msg::new("rewards-warning-block-2");
/// Placeables: none — the $DIG/percentages in this block are the SPEC-fixed `withdrawal_share_bps`
/// default (90/10) stated as prose, not `{$args}`, per the DECISIONS verbatim text.
pub const WARNING_BLOCK_3: Msg = Msg::new("rewards-warning-block-3");
/// Placeables: `committed_epochs` (twice), `committed_amount`, `committed_days`, `epoch_days` — all
/// via [`crate::i18n::Args::text`], never a raw number. `committed_amount` MUST be produced by
/// [`crate::amount::format_asset_amount`], never a typed numeral.
pub const WARNING_BLOCK_4: Msg = Msg::new("rewards-warning-block-4");
pub const WARNING_BLOCK_5: Msg = Msg::new("rewards-warning-block-5");
/// The closing line — DECISIONS-3253 requires this exact sentence be swept for verbatim, since it
/// is "the takeaway" a future pane could otherwise silently reword.
pub const WARNING_CLOSING: Msg = Msg::new("rewards-warning-closing");

/// The exact closing sentence, for the copy sweep to assert against (not for rendering — render
/// via [`WARNING_CLOSING`]).
pub const WARNING_CLOSING_LINE_EN: &str =
    "Downtime does not pause payment. It hands payment to a list that has stopped being true.";

// ---------------------------------------------------------------------------------------------
// Q3 — clawback confirm window (per commitment slot; no aggregate balance, ever).
// ---------------------------------------------------------------------------------------------

/// Placeable: `epoch_index`.
///
/// `pub(super)` (dig_ecosystem#3281), not `pub`: dropping this constant's own path to `pub(super)`
/// narrows who can name THIS `Msg` handle to the `rewards` module. That is reach-narrowing, not
/// unreachability -- see `super::clawback`'s module doc for the same distinction stated in full.
/// [`crate::i18n::Msg::new`] is a public `const fn` and the fluent key is a plain `&'static str`
/// literal, so any crate that writes `Msg::new("rewards-clawback-confirm-title")` still renders
/// this sentence with any amounts and any hash it likes -- no caller "can't forge" it in the sense
/// of being unable to reproduce the value; nothing here stops that. What IS true: the only value
/// in this crate whose text is bound to a commitment a real wallet key was proved to control is a
/// [`super::clawback::ProvenClawback`], producible only through
/// [`super::clawback::ProvenClawback::open`], which requires a
/// [`super::clawback::ClawbackAuthority`] -- see that module's doc for how `open` is gated.
/// `ALL_KEYS` below is private for the same reach-narrowing reason and stays walked only by this
/// module's own 14-locale completeness and forbidden-phrase sweeps.
pub(super) const CLAWBACK_CONFIRM_TITLE: Msg = Msg::new("rewards-clawback-confirm-title");
/// Placeables: `slot_amount`, `epoch_index`, `epoch_start_date`, `returned_amount`,
/// `forfeited_amount`, `clawback_ph_short`. Every value MUST come from the parsed commitment slot,
/// never from pane state (DECISIONS Q3: "the confirm window reads NOTHING from the pane's state").
///
/// `pub(super)`, same reasoning as [`CLAWBACK_CONFIRM_TITLE`] above.
pub(super) const CLAWBACK_CONFIRM_BODY: Msg = Msg::new("rewards-clawback-confirm-body");
/// Placeable: `returned_amount` — the approving click names the amount.
///
/// `pub(super)`, same reasoning as [`CLAWBACK_CONFIRM_TITLE`] above.
pub(super) const CLAWBACK_WITHDRAW_BUTTON: Msg = Msg::new("rewards-clawback-withdraw-button");
/// `pub(super)`, same reasoning as [`CLAWBACK_CONFIRM_TITLE`] above.
pub(super) const CLAWBACK_KEEP_BUTTON: Msg = Msg::new("rewards-clawback-keep-button");
/// No placeables, and deliberately no amount: shown when the commitment carries no recoverable
/// figure (the chain refuses the clawback, dig_ecosystem#3446). An absent figure must never read
/// as a zero. Reached only through [`super::clawback::ClawbackRefusal::sentence`].
pub(super) const CLAWBACK_NOT_RECOVERABLE: Msg = Msg::new("rewards-clawback-not-recoverable");
/// No placeables: shown when a commitment's recoverable figure exceeds what it committed, i.e. the
/// record contradicts itself. Distinct from [`CLAWBACK_NOT_RECOVERABLE`].
pub(super) const CLAWBACK_INCONSISTENT_RECORD: Msg =
    Msg::new("rewards-clawback-inconsistent-record");

// ---------------------------------------------------------------------------------------------
// Q3b — committed-incentives reading (dig_ecosystem#3290, SPEC §2.6 clause 5). Four states, never
// collapsed: a chain-read failure must never render as though nothing were committed, and neither
// may render as a bare zero.
// ---------------------------------------------------------------------------------------------

/// Placeable: `reason` — the underlying chain-read error, verbatim. Never rendered as a zero or as
/// "nothing committed"; see [`super::wire::CommitmentsReading::Unreadable`].
pub(super) const COMMITMENTS_UNREADABLE: Msg = Msg::new("rewards-commitments-unreadable");
/// Placeable: `observed_ago` — how long ago this (successful) read was taken, per SPEC §2.4's
/// staleness rule. Distinct from [`COMMITMENTS_UNREADABLE`]: this is a real, successful answer.
pub(super) const COMMITMENTS_NOTHING_COMMITTED: Msg =
    Msg::new("rewards-commitments-nothing-committed");
/// Placeables: `slot_count`, `observed_ago`. Never a recoverable-amount figure — see
/// [`super::wire::CommittedSlot`]'s doc, dig_ecosystem#3439.
pub(super) const COMMITMENTS_COMMITTED_SUMMARY: Msg =
    Msg::new("rewards-commitments-committed-summary");

// ---------------------------------------------------------------------------------------------
// Q3 — the irrevocable donation (`AddIncentives`) disclosure. Never on/adjacent to the fund
// button; lives under "Other ways to add $DIG", below the (default) Commit funding control.
// ---------------------------------------------------------------------------------------------

pub const DONATION_LABEL: Msg = Msg::new("rewards-donation-label");
pub const DONATION_BODY: Msg = Msg::new("rewards-donation-body");
/// The last line before the donation confirm window's buttons.
pub const DONATION_CONFIRM_LAST_LINE: Msg = Msg::new("rewards-donation-confirm-last-line");
/// Placeable: `amount`.
pub const DONATION_CONFIRM_BUTTON: Msg = Msg::new("rewards-donation-confirm-button");
pub const DONATION_CANCEL_BUTTON: Msg = Msg::new("rewards-donation-cancel-button");

// ---------------------------------------------------------------------------------------------
// SPEC §6.5.1 refill cadence and §2.4 staleness copy — final text, spec-dictated content.
// ---------------------------------------------------------------------------------------------

/// SPEC §6.5.1's literal required sentence shape: "at this funding rate a mirror clears the claim
/// threshold every N days". Placeable: `days`. Never rendered as, or accompanied by, a floor, a
/// minimum, a requirement or a gate — see [`crate::rewards::cadence`].
pub const REFILL_CADENCE: Msg = Msg::new("rewards-refill-cadence");

/// SPEC §2.4 clause 1: literal required rendering for an absent record ([`super::reading::ProverReading::NoRecord`]).
pub const STATUS_NOT_DISTRIBUTING: Msg = Msg::new("rewards-status-not-distributing");
/// SPEC §2.4 clause 2 / [`super::reading::ProverReading::NeverRan`] and
/// [`super::reading::PayoutReading::NeverRan`].
pub const STATUS_NEVER_RAN: Msg = Msg::new("rewards-status-never-ran");
/// SPEC §2.4 clause 3 / [`super::reading::EntrySetReading::Empty`] (never-written half).
pub const STATUS_ENTRY_COUNT_UNKNOWN: Msg = Msg::new("rewards-status-entry-count-unknown");
/// [`super::reading::ProverReading::ClockUnusable`] — DECISIONS Q4.2, must never render as fresh.
pub const STATUS_CLOCK_UNUSABLE: Msg = Msg::new("rewards-status-clock-unusable");
/// [`super::reading::ProverReading::HeartbeatLate`]. Placeable: `minutes`.
pub const STATUS_HEARTBEAT_LATE: Msg = Msg::new("rewards-status-heartbeat-late");
/// [`super::reading::ProverReading::HeartbeatLost`]. Placeables: `duration`, `observed_at_date`,
/// both routed through [`super::humanize`] (dig_ecosystem#3297) rather than a raw unix integer.
pub const STATUS_HEARTBEAT_LOST: Msg = Msg::new("rewards-status-heartbeat-lost");
/// [`super::reading::ProverReading::CycleOverdue`]. Placeables: `since_date`, `due_date`, both
/// routed through [`super::humanize`] (dig_ecosystem#3297).
pub const STATUS_CYCLE_OVERDUE: Msg = Msg::new("rewards-status-cycle-overdue");
/// [`super::reading::EntrySetReading::Empty`] (dig_ecosystem#3300) — true of BOTH "never written"
/// and "written, then evicted back to zero"; names neither history. Replaces the deleted
/// `rewards-entry-set-never-written`, which was false of the evicted case.
pub const ENTRY_SET_EMPTY: Msg = Msg::new("rewards-entry-set-empty");
/// "Paid out: nothing yet — this prover has never completed a cycle." — never a bare `0.000 $DIG`.
pub const PAID_OUT_NOTHING_YET: Msg = Msg::new("rewards-paid-out-nothing-yet");

// ---------------------------------------------------------------------------------------------
// dig_ecosystem#3253's correctness-gate fix: [`super::pane`]'s sentence builders routed to this
// catalog (they shipped hardcoded English in the same PR that added the keys above). These seven
// are the facts that had no existing key to route to; everything else in `pane.rs` reuses a key
// already defined above.
// ---------------------------------------------------------------------------------------------

/// [`super::reading::ProverReading::Live`] — the one prover state with nothing wrong to report.
pub const STATUS_LIVE: Msg = Msg::new("rewards-status-live");
/// [`super::reading::EntrySetReading::Known`]. Placeables: `entry_count`, `last_entry_write_at`
/// (routed through [`super::humanize::ago`] — dig_ecosystem#3297 — never a raw unix integer).
pub const ENTRY_SET_KNOWN: Msg = Msg::new("rewards-entry-set-known");
/// [`super::reading::PayoutReading::Paid`]. Placeables: `amount` (already through
/// [`crate::amount::amount_with_unit`], never a raw integer) and `last_cycle_completed_at`
/// (routed through [`super::humanize::ago`], same as [`ENTRY_SET_KNOWN`]).
pub const PAID_OUT_TOTAL: Msg = Msg::new("rewards-paid-out-total");
/// [`super::cadence::CadenceReading::NoMirrorsYet`] — a known, genuinely zero entry count; never
/// the same sentence as [`STATUS_ENTRY_COUNT_UNKNOWN`], which is an UNKNOWN count.
pub const CADENCE_NO_MIRRORS_YET: Msg = Msg::new("rewards-cadence-no-mirrors-yet");
/// [`super::cadence::CadenceReading::NoFundingRateChosen`] (adversarial gate finding 5) — mirrors
/// may exist and be claiming under a rate this pane has not chosen yet; never worded as
/// [`CADENCE_NO_MIRRORS_YET`].
pub const CADENCE_NO_FUNDING_RATE: Msg = Msg::new("rewards-cadence-no-funding-rate");
/// The sub-[`super::cadence::CLAIM_CADENCE_SECONDS`] clamp (finding 4): SPEC §8.6 fixes the peer's
/// own claim-attempt cadence at once a day, so a computed cadence under one day is unachievable,
/// not merely fast. Worded as the achievable floor, never as a promise of faster payment.
pub const CADENCE_SUB_DAY_FLOOR: Msg = Msg::new("rewards-cadence-sub-day-floor");
/// The far end of the SPEC §6.5.1 curve (finding 4), worded rather than a literal illegible day
/// count. Placeable: `days_threshold` (the rendering clamp past which a day count is worded).
pub const CADENCE_FAR_END: Msg = Msg::new("rewards-cadence-far-end");

// ---------------------------------------------------------------------------------------------
// dig_ecosystem#3253 -- the CREATE card itself: manager choice, coin picker, terms, submit and
// the pending-mint states. The sole production caller of every key below is
// `super::create_card` (paint lives in `confirm::gui::window::pane::store_rewards`, which calls
// through `create_card`'s pure sentence builders -- paint itself must stay I/O-free).
// ---------------------------------------------------------------------------------------------

/// "I understand" -- the button that turns a [`super::pane::WarningsShown`] witness into an
/// [`super::pane::Acknowledged`] gate.
pub const CREATE_ACK_BUTTON: Msg = Msg::new("rewards-create-ack-button");

/// Arm A's label -- "A key this app creates now".
pub const CREATE_MANAGER_ARM_A_LABEL: Msg = Msg::new("rewards-create-manager-arm-a-label");
/// Arm A's body. States ONLY the verified negative: built here, single-key, freezes forever if
/// lost. Must never contain "recovery", "recoverable", "safe", "secure" or "trusted" -- see
/// `create_card::forbidden_word_tests`.
pub const CREATE_MANAGER_ARM_A_BODY: Msg = Msg::new("rewards-create-manager-arm-a-body");
/// Arm B's label -- "A puzzle hash you supply".
pub const CREATE_MANAGER_ARM_B_LABEL: Msg = Msg::new("rewards-create-manager-arm-b-label");
/// Arm B's body. States ONLY that DIG cannot verify the supplied hash -- same forbidden-word bar
/// as [`CREATE_MANAGER_ARM_A_BODY`].
pub const CREATE_MANAGER_ARM_B_BODY: Msg = Msg::new("rewards-create-manager-arm-b-body");
/// The text field label for arm B's typed hash.
pub const CREATE_MANAGER_ARM_B_FIELD: Msg = Msg::new("rewards-create-manager-arm-b-field");
/// Arm B's field-level refusal, shown when the typed hash is not 32 bytes of hex. A disabled
/// Continue with nothing beside it does not say why it is disabled.
pub const CREATE_MANAGER_ARM_B_ERROR: Msg = Msg::new("rewards-create-manager-arm-b-error");

/// One coin-picker row. Placeable: `amount` (via [`crate::amount::format_asset_amount`]).
pub const CREATE_COIN_ROW: Msg = Msg::new("rewards-create-coin-row");
/// The listing omitted some coins. Placeable: `omitted`.
pub const CREATE_COIN_OMITTED: Msg = Msg::new("rewards-create-coin-omitted");
/// A `CatTransferError::Locked` coin -- rendered as locked, never folded into "no coins".
pub const CREATE_COIN_LOCKED: Msg = Msg::new("rewards-create-coin-locked");
/// The listing is genuinely empty.
pub const CREATE_COIN_EMPTY: Msg = Msg::new("rewards-create-coin-empty");

/// Terms: the epoch-length field label.
pub const CREATE_TERMS_EPOCH_LABEL: Msg = Msg::new("rewards-create-terms-epoch-label");
/// Terms: a zero epoch length is refused before the door ever sees it. Placeable: none.
pub const CREATE_TERMS_EPOCH_ZERO: Msg = Msg::new("rewards-create-terms-epoch-zero");
/// Terms: the first-epoch-start field label.
pub const CREATE_TERMS_FIRST_EPOCH_LABEL: Msg = Msg::new("rewards-create-terms-first-epoch-label");
/// Terms: a first-epoch start in the past is refused before the door ever sees it.
pub const CREATE_TERMS_FIRST_EPOCH_PAST: Msg = Msg::new("rewards-create-terms-first-epoch-past");
/// Terms: the network-fee field label.
pub const CREATE_TERMS_FEE_LABEL: Msg = Msg::new("rewards-create-terms-fee-label");
/// Terms: no confirmed, unspent XCH coin was found to fund the launch.
pub const CREATE_TERMS_NO_FUNDING_COIN: Msg = Msg::new("rewards-create-terms-no-funding-coin");
/// The store-root field's label -- the root that goes into the `LaunchComment` beside the store
/// id. Typed, because nothing pre-launch knows a store's root: the only root this pane ever reads
/// arrives on a `RewardDistributorStatusRecord`, which exists only once a distributor does.
pub const CREATE_TERMS_ROOT_LABEL: Msg = Msg::new("rewards-create-terms-root-label");
/// The store-root field's help line. The root is TYPED because nothing before a launch knows a
/// store's root, so the field has to say which root is the right one: the one this distributor is
/// meant to pay for, which is what goes into the `LaunchComment` peers discover it by.
pub const CREATE_TERMS_ROOT_HELP: Msg = Msg::new("rewards-create-terms-root-help");
/// The control that commits the manager choice and moves the card to its terms step.
pub const CREATE_CONTINUE: Msg = Msg::new("rewards-create-continue");

/// The submit button -- "Sign and submit".
pub const CREATE_SUBMIT_BUTTON: Msg = Msg::new("rewards-create-submit-button");
/// `MintError::Locked` at submit time -- the account locked between opening the card and
/// pressing submit.
pub const CREATE_SUBMIT_LOCKED: Msg = Msg::new("rewards-create-submit-locked");
/// [`super::create_sink::Refused::Busy`] -- another account action (a tray action, or another
/// create) already held the shared worker when this one was submitted. The job was dropped, never
/// queued; see `create_sink`'s module doc for why.
pub const CREATE_BUSY: Msg = Msg::new("rewards-create-busy");

/// `reward_create_job`'s pre-flight checks (dig_ecosystem#3367), all in `bin/dig-app.rs`, before a
/// door is ever built -- see that function's own doc for why each is a `record_submit_error` call
/// rather than a silent return.
///
/// No account session is open when the job runs -- there is nothing left to sign with.
pub const CREATE_SUBMIT_NOT_OPEN: Msg = Msg::new("rewards-create-submit-not-open");
/// DIG's own status lock could not be read -- distinct from [`CREATE_SUBMIT_CHAIN_UNREACHABLE`]:
/// this is DIG failing to read ITS OWN state, not the chain.
pub const CREATE_SUBMIT_STATE_UNREAD: Msg = Msg::new("rewards-create-submit-state-unread");
/// The node engine has no live endpoint to publish a spend through.
pub const CREATE_SUBMIT_CHAIN_UNREACHABLE: Msg =
    Msg::new("rewards-create-submit-chain-unreachable");
/// The account is locked at the moment `reward_create_job` reads `reward_distributor_minter()` --
/// distinct from [`CREATE_SUBMIT_LOCKED`], which is `MintError::Locked` inside `submit` itself,
/// after a door already exists. Different key so the two lock windows stay independently
/// traceable to their own call sites.
pub const CREATE_SUBMIT_LOCKED_RETRY: Msg = Msg::new("rewards-create-submit-locked-retry");
/// `MintError::Rejected` -- the network said no to the push, so no funds moved. A CLOSED sentence:
/// the node-relayed rejection reason never reaches it (dig_ecosystem#3457).
pub const CREATE_SUBMIT_REJECTED: Msg = Msg::new("rewards-create-submit-rejected");
/// `MintError::ChainUnreachable` and any unrecognised `MintError` -- the push's outcome is
/// unknown, so this must NOT claim nothing was submitted (contrast
/// [`CREATE_SUBMIT_CHAIN_UNREACHABLE`], which fires before any bundle exists).
pub const CREATE_SUBMIT_OUTCOME_UNKNOWN: Msg = Msg::new("rewards-create-submit-outcome-unknown");
/// `MintError::{Build, Refused, ReservationUnusable, Journal, RecordRejected}` -- every one of
/// them is raised before a bundle is pushed, so nothing was submitted.
pub const CREATE_SUBMIT_NOT_BUILT: Msg = Msg::new("rewards-create-submit-not-built");

/// A pending mint that has not yet been buried -- MUST contain the verbatim substring
/// "submitted to the mempool — not yet on chain" (dig_ecosystem#3253 acceptance bar; dash
/// typography corrected dig_ecosystem#3374) and show the block count. Placeables: `blocks`,
/// `predicted_id`.
pub const CREATE_AWAITING: Msg = Msg::new("rewards-create-awaiting");
/// A pending mint that is now buried and confirmed. Deliberately not "created!" as a banner --
/// see [`super::create_card`]'s module doc: the pane's EXISTING `rewards_sections` render the
/// live distributor from here on; this is only the bridging line the pending slot shows once.
pub const CREATE_CONFIRMED: Msg = Msg::new("rewards-create-confirmed");
/// A pending mint the chain reports as failed. Placeable: `reason` -- the real reason, never
/// "unknown".
pub const CREATE_FAILED: Msg = Msg::new("rewards-create-failed");
/// `status(&chain)` returned `Err` -- never rendered as failure or success; the pending state is
/// kept.
pub const CREATE_STATUS_UNKNOWN: Msg = Msg::new("rewards-create-status-unknown");

/// Every key this module defines, for the exhaustiveness/render/sweep tests below. Keeping this
/// list here (rather than re-deriving it per test) is the one place a new key must be added or the
/// tests that iterate "every rewards key" silently stop covering it.
///
/// `#[cfg(test)]`, not `pub` (dig_ecosystem#3281 S2): its only callers are this module's own
/// `every_copy_key_renders_in_the_active_language` and `no_rewards_copy_contains_a_forbidden_phrase`
/// tests below (verified: no other file in the crate names `ALL_KEYS`), so gating it to test
/// builds costs nothing -- and is required, not just tidier: a plain private (non-`pub`) const
/// with no non-test caller is genuinely dead code in a `--no-default-features` release build and
/// trips `-D warnings`' dead-code lint. A `pub` `ALL_KEYS` re-exported all four `CLAWBACK_*` keys
/// BY VALUE regardless of their own `pub(super)`, so `ALL_KEYS[8].with(..)` rendered the full
/// confirm body from outside this crate with no [`super::clawback::ClawbackAuthority`] witness at
/// all -- narrower than a forbidden literal or constant name, so a source-scan guard could not see
/// it. Narrowing this is reach-narrowing too: a caller can still write the literal key and call
/// the public [`Msg::new`] directly (see [`CLAWBACK_CONFIRM_TITLE`]'s doc above).
#[cfg(test)]
const ALL_KEYS: &[Msg] = &[
    WARNING_HEADING,
    WARNING_BLOCK_1,
    WARNING_BLOCK_2,
    WARNING_BLOCK_3,
    WARNING_BLOCK_4,
    WARNING_BLOCK_5,
    WARNING_CLOSING,
    CLAWBACK_CONFIRM_TITLE,
    CLAWBACK_CONFIRM_BODY,
    CLAWBACK_WITHDRAW_BUTTON,
    CLAWBACK_KEEP_BUTTON,
    CLAWBACK_NOT_RECOVERABLE,
    CLAWBACK_INCONSISTENT_RECORD,
    COMMITMENTS_UNREADABLE,
    COMMITMENTS_NOTHING_COMMITTED,
    COMMITMENTS_COMMITTED_SUMMARY,
    DONATION_LABEL,
    DONATION_BODY,
    DONATION_CONFIRM_LAST_LINE,
    DONATION_CONFIRM_BUTTON,
    DONATION_CANCEL_BUTTON,
    REFILL_CADENCE,
    STATUS_NOT_DISTRIBUTING,
    STATUS_NEVER_RAN,
    STATUS_ENTRY_COUNT_UNKNOWN,
    STATUS_CLOCK_UNUSABLE,
    STATUS_HEARTBEAT_LATE,
    STATUS_HEARTBEAT_LOST,
    STATUS_CYCLE_OVERDUE,
    ENTRY_SET_EMPTY,
    PAID_OUT_NOTHING_YET,
    STATUS_LIVE,
    ENTRY_SET_KNOWN,
    PAID_OUT_TOTAL,
    CADENCE_NO_MIRRORS_YET,
    CADENCE_NO_FUNDING_RATE,
    CADENCE_SUB_DAY_FLOOR,
    CADENCE_FAR_END,
    CREATE_ACK_BUTTON,
    CREATE_MANAGER_ARM_A_LABEL,
    CREATE_MANAGER_ARM_A_BODY,
    CREATE_MANAGER_ARM_B_LABEL,
    CREATE_MANAGER_ARM_B_BODY,
    CREATE_MANAGER_ARM_B_FIELD,
    CREATE_MANAGER_ARM_B_ERROR,
    CREATE_TERMS_ROOT_HELP,
    CREATE_COIN_ROW,
    CREATE_COIN_OMITTED,
    CREATE_COIN_LOCKED,
    CREATE_COIN_EMPTY,
    CREATE_TERMS_EPOCH_LABEL,
    CREATE_TERMS_EPOCH_ZERO,
    CREATE_TERMS_FIRST_EPOCH_LABEL,
    CREATE_TERMS_FIRST_EPOCH_PAST,
    CREATE_TERMS_FEE_LABEL,
    CREATE_TERMS_NO_FUNDING_COIN,
    CREATE_TERMS_ROOT_LABEL,
    CREATE_CONTINUE,
    CREATE_SUBMIT_BUTTON,
    CREATE_SUBMIT_LOCKED,
    CREATE_BUSY,
    CREATE_SUBMIT_NOT_OPEN,
    CREATE_SUBMIT_STATE_UNREAD,
    CREATE_SUBMIT_CHAIN_UNREACHABLE,
    CREATE_SUBMIT_LOCKED_RETRY,
    CREATE_SUBMIT_REJECTED,
    CREATE_SUBMIT_OUTCOME_UNKNOWN,
    CREATE_SUBMIT_NOT_BUILT,
    CREATE_AWAITING,
    CREATE_CONFIRMED,
    CREATE_FAILED,
    CREATE_STATUS_UNKNOWN,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Args;
    use crate::rewards::source_scan;

    /// Every key exists and renders SOMETHING in the active (English, by default) language — not a
    /// content check, just that the wiring reaches the catalog at all. Content correctness is
    /// `i18n::tests`'s job crate-wide (key completeness across all 14 locales, placeable agreement,
    /// no torn runs, brand-literal survival, digit-injection, non-English-in-disguise).
    #[test]
    fn every_copy_key_renders_in_the_active_language() {
        for msg in ALL_KEYS {
            assert!(!msg.text().is_empty(), "{} rendered empty", msg.key());
        }
    }

    /// The five warning blocks plus heading and closing line must all be present and non-empty at
    /// once — DECISIONS-3253 rendering rule 1 forbids truncation/collapse/pagination, and a key
    /// that silently rendered empty would be exactly that.
    #[test]
    fn all_five_warning_blocks_and_the_closing_line_render() {
        for msg in [
            WARNING_HEADING,
            WARNING_BLOCK_1,
            WARNING_BLOCK_2,
            WARNING_BLOCK_3,
            WARNING_BLOCK_5,
            WARNING_CLOSING,
        ] {
            assert!(!msg.text().is_empty());
        }
        let block_4 = WARNING_BLOCK_4.with(
            &Args::new()
                .text("committed_epochs", "2")
                .text("committed_amount", "10 $DIG")
                .text("committed_days", "14")
                .text("epoch_days", "7"),
        );
        assert!(!block_4.is_empty());
    }

    /// DECISIONS-3253's closing line is the takeaway a future pane could reword without noticing;
    /// this pins the English catalog value to the verbatim sentence.
    #[test]
    fn closing_line_is_verbatim() {
        assert_eq!(
            WARNING_CLOSING.text_in(crate::i18n::Language::En),
            WARNING_CLOSING_LINE_EN
        );
    }

    /// DECISIONS-3253's donation label copy test: the label must contain "cannot be withdrawn".
    #[test]
    fn donation_label_contains_cannot_be_withdrawn() {
        let text = DONATION_LABEL.text_in(crate::i18n::Language::En);
        assert!(
            text.contains("cannot be withdrawn"),
            "donation label must say the $DIG cannot be withdrawn: {text:?}"
        );
    }

    /// The forbidden-phrase copy sweep (DECISIONS-3253's acceptance list) over every rewards
    /// English catalog value, phrase for phrase. dig-app-core has no pre-existing crate-wide
    /// copy-voice sweep to extend (searched: no `_sweep`/`copy_voice` fn outside this module at
    /// the time of writing) — this sweep is the seed one; a future pane's own copy module should
    /// gain an identical block over its own [`super::ALL_KEYS`]-equivalent rather than rely on this
    /// one reaching outside its module.
    #[test]
    fn no_rewards_copy_contains_a_forbidden_phrase() {
        const FORBIDDEN: &[&str] = &[
            "requires uptime",
            "keep your node online",
            "stay online",
            "rewards stop",
            "minimum funding",
            "funding floor",
            "at least",
            // Widened from the compound phrases above to the bare words: "floor" and "gate" say
            // the same forbidden thing ("under this, it fails") even without "funding" or
            // "minimum" attached, and DECISIONS-3253 / cadence.rs's own doc withdraw that claim
            // entirely (SPEC §8.6 skips a sub-threshold claim rather than failing it).
            "floor",
            "gate",
        ];
        for msg in ALL_KEYS {
            let text = msg.text_in(crate::i18n::Language::En).to_lowercase();
            for phrase in FORBIDDEN {
                assert!(
                    !text.contains(phrase),
                    "{} contains forbidden phrase {phrase:?}: {text:?}",
                    msg.key()
                );
            }
        }
    }

    /// Regression for dig_ecosystem#3374: `rewards-status-never-ran` used to render as the bare
    /// fragment "Never ran" -- indistinguishable, to a reader deciding about money, from a
    /// truncated or unknown value. `ProverReading::NeverRan` IS a decoded state (see
    /// `reading.rs`'s doc comment), so the catalog text must say what that decoded state MEANS: a
    /// complete sentence naming the consequence, in the register `rewards-status-live` and
    /// `rewards-status-cycle-overdue` already use.
    #[test]
    fn never_ran_status_is_a_complete_sentence_not_a_bare_fragment() {
        let text = STATUS_NEVER_RAN.text_in(crate::i18n::Language::En);
        assert!(
            text.trim_end_matches('.').split(' ').count() >= 4,
            "STATUS_NEVER_RAN must be a complete sentence naming the consequence, not a bare \
             fragment like \"Never ran\": {text:?}"
        );
        assert_ne!(
            text, "Never ran",
            "STATUS_NEVER_RAN must not render the old bare fragment"
        );
    }

    /// Regression for dig_ecosystem#3374: a raw ASCII double-hyphen used as a dash reads as a
    /// rendering defect on a surface where a reader decides about money -- every rewards-facing
    /// catalog value must use proper dash typography instead.
    #[test]
    fn no_rewards_copy_contains_the_ascii_double_hyphen() {
        for msg in ALL_KEYS {
            let text = msg.text_in(crate::i18n::Language::En);
            assert!(
                !text.contains("--"),
                "{} uses a raw ASCII double-hyphen instead of proper dash typography: {text:?}",
                msg.key()
            );
        }
    }

    /// Keys this guard does NOT enforce yet, each for a reason already on record elsewhere in
    /// this crate -- not a workaround, a transcription of a gap this ticket does not own:
    ///
    /// - The five warning blocks + heading + closing line: `pane.rs`'s own doc on
    ///   `REQUIRED_WARNING_KEYS` says the paint step is "deferred to the commit that paints the
    ///   five blocks" -- the acknowledgement gate ([`super::pane::WarningsShown`]) shipped, the
    ///   rendering did not, and this ticket's HARD LIMITS forbid touching `WarningsShown`/
    ///   `CreationGate`.
    /// - The five donation keys: no donation control is built in this crate at all (the create
    ///   control that DID land in this pass is `create_card`, which uses none of these keys).
    const NOT_YET_ENFORCED: &[&str] = &[
        "DONATION_LABEL",
        "DONATION_BODY",
        "DONATION_CONFIRM_LAST_LINE",
        "DONATION_CONFIRM_BUTTON",
        "DONATION_CANCEL_BUTTON",
    ];

    /// Guard against dig_ecosystem#3253's B-plain finding: eight ratified, translated, reviewed
    /// `Msg` constants (`rewards-create-not-offered`, `rewards-refill-not-offered`, the three
    /// `rewards-one-way-door-*` keys, `rewards-commitment-depth-bound`, and the two
    /// `rewards-reserve-*` keys) shipped defined, listed in [`ALL_KEYS`], sweep-tested and
    /// 14-locale-complete -- and were never rendered to a person, because no production caller in
    /// `pane.rs` or `clawback.rs` ever named them outside a test function. This test exists to
    /// keep that from happening again: it fails if any `Msg` constant this module declares is
    /// referenced ONLY from test code (or not referenced anywhere outside this file at all),
    /// unless it is named in [`NOT_YET_ENFORCED`] above.
    ///
    /// A guard whose purpose is not written gets deleted by the next person who finds it
    /// inconvenient -- this exact surface already lost one guard,
    /// `activity_tab_emits_zero_action_rows`, to a false premise. This one's premise: `pane.rs`
    /// and `clawback.rs` are the only two production consumers of this module's keys, so scanning
    /// their source with `#[cfg(test)]` test-module bodies, comment lines, `use` items and
    /// `#[allow(dead_code)]`-marked item bodies ALL stripped out tells you whether a real sentence
    /// builder -- not a test, a doc mention, an import list, or a builder the compiler would have
    /// flagged dead had the lint not been silenced -- is the one naming a given key. A line-for-line
    /// port of this file's own scan functions, run outside the Rust toolchain against
    /// dig_ecosystem#3253's `67bd7ae6` (the tree where all eight keys still existed, named only in
    /// an import list and two `#[allow(dead_code)]` builders), flags all eight where the
    /// pre-fix version flagged five -- this repo's own `Test + coverage` CI run of this exact test
    /// is the authoritative execution, not the port.
    /// Every accessor in `create_card.rs` that renders one of this module's create-card or warning
    /// keys, and therefore every accessor the PAINT code must name.
    ///
    /// `every_msg_constant_is_reachable_outside_test_code` above proves a key is named by a
    /// production sentence builder. It cannot prove that builder is ever CALLED -- a whole card's
    /// worth of accessors sitting in `create_card.rs` with no paint behind them satisfies it
    /// exactly as well as a painted card does, which is the same unreachability one level up. So
    /// this test scans the paint module itself.
    const PAINTED_ACCESSORS: &[&str] = &[
        "warning_heading",
        "warning_block_1",
        "warning_block_2",
        "warning_block_3",
        "warning_block_4",
        "warning_block_5",
        "warning_closing",
        "ack_button_label",
        "manager_arm_a_label",
        "manager_arm_a_body",
        "manager_arm_b_label",
        "manager_arm_b_body",
        "manager_arm_b_field_label",
        "coin_row_sentence",
        "coin_omitted_sentence",
        "coin_locked_sentence",
        "coin_empty_sentence",
        "terms_epoch_label",
        "terms_first_epoch_label",
        "terms_fee_label",
        "terms_root_label",
        "terms_root_help",
        "manager_arm_b_error",
        "ladder_stage",
        "record_acknowledgement",
        "commit_manager_choice",
        "continue_button_label",
        "submit_button_label",
        "validate_epoch_terms",
        "select_funding_coin",
        "sink_installed",
        "attempt_submit",
        "cached_inputs",
        "cached_availability",
        "last_rendered",
    ];

    /// The card's accessors are named by the code that PAINTS it, not only by the module that
    /// declares them -- see [`PAINTED_ACCESSORS`].
    ///
    /// Parsed, not cut: the paint file's production items are what is left after every
    /// `#[cfg(test)]` item is dropped, which includes the `#[cfg(test)] #[path = ..] mod tests;`
    /// declaration, so the sibling test file never reads as production. A key mentioned only in
    /// a comment is not an identifier, so it cannot stand in for a call.
    #[test]
    fn every_create_card_accessor_is_named_by_the_paint_code() {
        const PAINT: &str = "../confirm/gui/window/pane/store_rewards.rs";
        let paint = source_scan::production_at(
            PAINT,
            include_str!("../confirm/gui/window/pane/store_rewards.rs"),
        );

        assert!(
            source_scan::fn_named(&paint, "create_card_steps").is_some(),
            "the parse lost the paint code itself -- this test would then pass vacuously"
        );

        let named = source_scan::idents(&paint);
        let unpainted: Vec<&str> = PAINTED_ACCESSORS
            .iter()
            .copied()
            .filter(|name| !named.contains(*name))
            .collect();

        assert!(
            unpainted.is_empty(),
            "create-card accessor(s) {unpainted:?} are declared in create_card.rs but never named \
             by store_rewards.rs's paint code -- a ratified, translated sentence with a builder \
             and no caller is the same unreachable string, one level up."
        );
    }

    /// Every `pub` `Msg` constant `copy.rs` declares, by name: a const whose type is `Msg` and
    /// whose visibility is anything but private.
    fn declared_msg_constant_names(file: &syn::File) -> Vec<String> {
        source_scan::consts(file)
            .iter()
            .filter(|constant| !matches!(constant.vis, syn::Visibility::Inherited))
            .filter(|constant| source_scan::normalized(&*constant.ty) == "Msg")
            .map(|constant| constant.ident.to_string())
            .collect()
    }

    /// Every `Msg` constant is named by REACHABLE production code in one of the four consumers:
    /// not a `use` list, not an `#[allow(dead_code)]` item, not a comment, not test code (all
    /// removed by [`source_scan::reachable`]). The tray binary (`dig-app`, a separate crate) is a
    /// consumer as of dig_ecosystem#3367: `reward_create_job` renders four of these keys directly,
    /// so without it they would read as unreachable even though a real person sees them.
    #[test]
    fn every_msg_constant_is_reachable_outside_test_code() {
        let copy = source_scan::production_at("copy.rs", include_str!("copy.rs"));

        let mut named = std::collections::BTreeSet::new();
        for (path, src) in [
            ("pane.rs", include_str!("pane.rs")),
            ("clawback.rs", include_str!("clawback.rs")),
            ("create_card.rs", include_str!("create_card.rs")),
            (
                "dig-app/src/bin/dig-app.rs",
                include_str!("../../../dig-app/src/bin/dig-app.rs"),
            ),
        ] {
            named.extend(source_scan::idents(&source_scan::reachable_at(path, src)));
        }

        let declared = declared_msg_constant_names(&copy);
        assert!(
            !declared.is_empty(),
            "no Msg constants found in copy.rs -- the scan is broken"
        );

        let unreachable: Vec<&String> = declared
            .iter()
            .filter(|name| !NOT_YET_ENFORCED.contains(&name.as_str()))
            .filter(|name| !named.contains(*name))
            .collect();

        assert!(
            unreachable.is_empty(),
            "Msg constant(s) {unreachable:?} are declared in copy.rs but never named by any \
             production sentence builder in pane.rs/clawback.rs -- only test code, a doc mention, \
             or nothing reaches them. Wire them into a real caller or delete them; do not leave a \
             translated, reviewed string no one can ever see."
        );
    }
}
