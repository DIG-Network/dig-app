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

// ---------------------------------------------------------------------------------------------
// Q3b — committed-incentives reading (dig_ecosystem#3290, SPEC §2.6 clause 5). Four states, never
// collapsed: a chain-read failure must never render as though nothing were committed, and neither
// may render as a bare zero.
// ---------------------------------------------------------------------------------------------

/// Placeable: `reason` — the underlying chain-read error, verbatim. Never rendered as a zero or as
/// "nothing committed"; see [`super::wire::CommitmentsReading::Unreadable`].
pub(super) const COMMITMENTS_UNREADABLE: Msg = Msg::new("rewards-commitments-unreadable");
/// No placeables. Distinct from [`COMMITMENTS_NOTHING_COMMITTED`]: there is no distributor to have
/// committed anything, which is a different fact than a real distributor with an empty commitment
/// set.
pub(super) const COMMITMENTS_NO_DISTRIBUTOR: Msg = Msg::new("rewards-commitments-no-distributor");
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
    COMMITMENTS_UNREADABLE,
    COMMITMENTS_NO_DISTRIBUTOR,
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
    CREATE_AWAITING,
    CREATE_CONFIRMED,
    CREATE_FAILED,
    CREATE_STATUS_UNKNOWN,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Args;
    use crate::rewards::test_scan::strip_comment_lines;

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
    #[test]
    fn every_create_card_accessor_is_named_by_the_paint_code() {
        // Cut at the test-module DECLARATION, not at the first `#[cfg(test)]`.
        //
        // Neither of the other two devices works on this file. `strip_all_test_mods` walks braces
        // and that module has no body -- it is `#[path = "store_rewards_tests.rs"] mod tests;`,
        // pointing at a sibling file. And splitting on the first `#[cfg(test)]` cuts at a small
        // test-only helper hundreds of lines ABOVE the paint code, throwing the whole card away
        // and passing this test for the worst possible reason: nothing left to find.
        //
        // What survives the cut is the module's production text plus one `#[cfg(test)]` lock
        // helper, which names no accessor. Comments are stripped so a key mentioned only in a doc
        // comment cannot stand in for a call.
        let paint_source = include_str!("../confirm/gui/window/pane/store_rewards.rs")
            .split("#[path = \"store_rewards_tests.rs\"]")
            .next()
            .expect("store_rewards.rs always declares its sibling test module");
        let paint = strip_comment_lines(paint_source);

        assert!(
            paint.contains("fn create_card_steps"),
            "the cut removed the paint code itself -- this test would then pass vacuously"
        );

        let unpainted: Vec<&str> = PAINTED_ACCESSORS
            .iter()
            .copied()
            .filter(|name| !contains_word(&paint, name))
            .collect();

        assert!(
            unpainted.is_empty(),
            "create-card accessor(s) {unpainted:?} are declared in create_card.rs but never named              by store_rewards.rs's paint code -- a ratified, translated sentence with a builder              and no caller is the same unreachable string, one level up."
        );
    }

    #[test]
    fn every_msg_constant_is_reachable_outside_test_code() {
        // Production text of THIS file: everything before its own `#[cfg(test)]` tail (`ALL_KEYS`
        // onward), which never counts as a "reference" -- it exists only so these tests can
        // iterate every key, not because any of them renders a sentence.
        let copy_production = include_str!("copy.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("copy.rs always has a #[cfg(test)] section");

        let pane_production = strip_all_test_mods(include_str!("pane.rs"));
        let clawback_production = strip_all_test_mods(include_str!("clawback.rs"));
        let create_card_production = strip_all_test_mods(include_str!("create_card.rs"));
        // The tray binary itself (`dig-app`, a SEPARATE crate from this one) is a fourth
        // production consumer as of dig_ecosystem#3367: `reward_create_job` renders four of this
        // module's keys directly, with no `dig-app-core` intermediary. Without this file, those
        // four keys would read as unreachable here even though a real person sees them -- the
        // crate boundary, not a missing caller, would be the false positive.
        let tray_production =
            strip_all_test_mods(include_str!("../../../dig-app/src/bin/dig-app.rs"));
        let production = harden_production_text(&format!(
            "{pane_production}{clawback_production}{create_card_production}{tray_production}"
        ));

        let unreachable: Vec<&str> = declared_msg_constant_names(copy_production)
            .into_iter()
            .filter(|name| !NOT_YET_ENFORCED.contains(name))
            .filter(|name| !contains_word(&production, name))
            .collect();

        assert!(
            unreachable.is_empty(),
            "Msg constant(s) {unreachable:?} are declared in copy.rs but never named by any \
             production sentence builder in pane.rs/clawback.rs -- only test code, a doc mention, \
             or nothing reaches them. Wire them into a real caller or delete them; do not leave a \
             translated, reviewed string no one can ever see."
        );
    }

    /// Runs every text-level hatch-closer over a production source blob. Order matters for exactly
    /// ONE pair, and it is not the one the previous version of this doc claimed: comments must be
    /// stripped FIRST, before both the dead-code-item scan and the `use`-item scan. Dead-code
    /// stripping and `use` stripping are themselves order-independent here -- traced: the real
    /// reference to a key always lives in the `.with()` call inside a dead builder's body, never in
    /// the import line itself, so which of those two runs first cannot change the outcome.
    ///
    /// Comments-first closes two adversarial-gate findings at once (dig_ecosystem#3253):
    /// - a `#[allow(dead_code)]` marker written only inside a `//` comment, left in place, would be
    ///   found by the dead-code scan anyway and consume whatever real item happens to sit next --
    ///   stripping the comment first removes the marker before that scan ever runs;
    /// - a semicolon sitting inside a `//` comment INSIDE a multi-line `use { ... }` group ended
    ///   `strip_use_items`'s skip early on the old (comments-last) ordering, splicing the group's
    ///   remainder back in as "production text" and silently restoring the import hatch.
    ///
    /// The two findings already on record before this fix still apply to what's left after
    /// comments are gone:
    /// - a constant named only in a `use { ... }` import list reads as "referenced from
    ///   production" to a plain `contains_word` scan, even though nothing ever calls `.with(...)`
    ///   on it (finding 2);
    /// - a `pub(crate)` builder marked `#[allow(dead_code)]` is, by definition, code the compiler
    ///   would otherwise have flagged as unreachable from any real call site; naming a key only
    ///   inside such a builder is the same unreachability the whole guard exists to catch, not an
    ///   exemption from it (finding 3).
    fn harden_production_text(src: &str) -> String {
        strip_use_items(&strip_dead_code_allowed_items(&strip_comment_lines(src)))
    }

    /// Removes every item (attribute line through its own end) that carries an
    /// `#[allow(dead_code)]` attribute directly above it. A builder silenced this way is a
    /// text-scannable proxy for "the compiler would have told you this is unreachable and we
    /// silenced it" -- a `Msg` constant named only inside one is not reachable from production,
    /// no matter how plausible the builder's own doc comment reads.
    fn strip_dead_code_allowed_items(src: &str) -> String {
        let marker = "#[allow(dead_code)]";
        let mut result = src.to_string();
        while let Some(pos) = result.find(marker) {
            result = remove_dead_code_item(&result, pos);
        }
        result
    }

    /// Removes ONE `#[allow(dead_code)]`-marked item, bounded at whichever comes first downstream:
    /// the next `;` (a brace-free item -- a `const`, `type` alias, tuple struct, enum variant or
    /// field) or the next `{` (a brace-delimited item -- `fn`, `struct`, `enum`, `impl`). The old
    /// version of this function always took "the next `{` anywhere downstream", so a brace-free
    /// marked item ran the removal into an unrelated function's entire body -- reproduced by the
    /// adversarial gate against this file's own `STATUS_LIVE`/`pane.rs` pair, which made seven
    /// shipped, reachable status keys read as unreachable.
    fn remove_dead_code_item(src: &str, item_start: usize) -> String {
        let rest = &src[item_start..];
        match (rest.find('{'), rest.find(';')) {
            (Some(brace), Some(semi)) if semi < brace => {
                format!("{}{}", &src[..item_start], &src[item_start + semi + 1..])
            }
            (Some(_), _) => remove_brace_block(src, item_start),
            (None, Some(semi)) => {
                format!("{}{}", &src[..item_start], &src[item_start + semi + 1..])
            }
            (None, None) => panic!("dead-code item at {item_start} has neither `{{` nor `;`"),
        }
    }

    /// Removes every `use ...;` item, including ones whose braced list spans multiple lines, and
    /// all visibility-prefixed variants (`pub use`, `pub(crate) use`, `pub(super) use`,
    /// `pub(in ...) use`). A constant named only inside a `use super::copy::{...}` list is
    /// imported, not referenced -- nothing downstream of the import calls `.with(...)` on it --
    /// so it must not count as a production reference just because the identifier appears in the
    /// source text. This holds for all visibility variants: a key in a `pub use` list is not a
    /// production reference either.
    fn strip_use_items(src: &str) -> String {
        let mut out = String::new();
        let mut skipping = false;
        for line in src.lines() {
            if !skipping {
                let trimmed = line.trim_start();
                let is_use_item = trimmed.starts_with("use ")
                    || trimmed.starts_with("pub use ")
                    || trimmed.starts_with("pub(crate) use ")
                    || trimmed.starts_with("pub(super) use ")
                    || (trimmed.starts_with("pub(in ") && trimmed.contains(") use "));

                if is_use_item {
                    skipping = true;
                }
            }
            if skipping {
                if line.contains(';') {
                    skipping = false;
                }
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// Synthetic-fixture guard for `harden_production_text`'s scan functions (dig_ecosystem#3253
    /// reviewer finding B): drives all four shapes over inline `&'static str` fixtures owned right
    /// here, not real files, so CI re-runs it on every change and it cannot go stale the way a
    /// hand port outside the toolchain does. No fixture is ever a `&str` borrowed from a dropped
    /// local or produced via `transmute` -- each is a `const` string literal.
    #[test]
    fn harden_production_text_handles_all_four_synthetic_shapes() {
        // Shape 1: a key named only in a `use` import list must be flagged (not reachable).
        const USE_ONLY: &str = r#"
use super::copy::{ONLY_IMPORTED_KEY};
"#;
        assert!(
            !contains_word(&harden_production_text(USE_ONLY), "ONLY_IMPORTED_KEY"),
            "a use-only reference must not count as reachable"
        );

        // Shape 2: a key named only inside an `#[allow(dead_code)]` builder body must be flagged.
        const DEAD_CODE_BODY_ONLY: &str = r#"
#[allow(dead_code)]
fn dead_builder() {
    let _ = DEAD_CODE_ONLY_KEY;
}
"#;
        assert!(
            !contains_word(
                &harden_production_text(DEAD_CODE_BODY_ONLY),
                "DEAD_CODE_ONLY_KEY"
            ),
            "a dead-code-only reference must not count as reachable"
        );

        // Shape 3 (finding A, over-strip): a brace-free `#[allow(dead_code)]` item followed by a
        // real builder -- the real builder's own key must stay reachable, not get swallowed by an
        // unbounded brace scan running past the dead item into the next function.
        // The literal is split with concat!() so every_msg_key_in_source() (i18n/tests.rs) does
        // not mistake this guard fixture for a product key; rejoining it would turn the parity
        // test red and hide that the guard is exercising the right surface.
        const BRACE_FREE_DEAD_ITEM_THEN_REAL_BUILDER: &str = concat!(
            "#[allow(dead_code)]\n",
            "const UNUSED_CONST: Msg = Msg::",
            "new(\"rewards-guard-fixture-unreachable\");\n",
            "\n",
            "fn real_builder() {\n",
            "    let _ = REAL_KEY_AFTER_BRACE_FREE_ITEM;\n",
            "}\n",
        );
        assert!(
            contains_word(
                &harden_production_text(BRACE_FREE_DEAD_ITEM_THEN_REAL_BUILDER),
                "REAL_KEY_AFTER_BRACE_FREE_ITEM"
            ),
            "a real builder after a brace-free dead-code item must stay reachable"
        );

        // Shape 4 (finding A, comments-first): `#[allow(dead_code)]` appearing only inside a `//`
        // comment above a real builder -- that builder's own key must stay reachable, not get
        // swallowed because the marker was matched inside the (not-yet-stripped) comment.
        const MARKER_ONLY_IN_COMMENT_THEN_REAL_BUILDER: &str = r#"
// #[allow(dead_code)]
fn real_builder_after_comment() {
    let _ = REAL_KEY_AFTER_COMMENT_MARKER;
}
"#;
        assert!(
            contains_word(
                &harden_production_text(MARKER_ONLY_IN_COMMENT_THEN_REAL_BUILDER),
                "REAL_KEY_AFTER_COMMENT_MARKER"
            ),
            "a real builder after a comment-only marker mention must stay reachable"
        );
    }

    /// Proves that `strip_use_items` removes all visibility-prefixed `use` statements, including
    /// `pub use`, `pub(crate) use`, `pub(super) use`, and `pub(in ...) use` forms. A constant
    /// named only in a `pub use` import list must not satisfy the reachability guard, just as a
    /// constant named only in a plain `use` list does not.
    #[test]
    fn strip_use_items_removes_all_visibility_variants() {
        // The literal is split with concat!() so every_msg_key_in_source() (i18n/tests.rs) does
        // not mistake this guard fixture for a product key; rejoining it would turn the parity
        // test red and hide that the guard is exercising the right surface.
        let src_with_pub_use = concat!(
            "pub const REAL_CONSTANT: Msg = Msg::",
            "new(\"rewards-guard-fixture-reachable\");\n",
            "pub use super::copy::{TEST_CONSTANT};\n",
            "\n",
            "fn builder() {\n",
            "    let _ = REAL_CONSTANT;\n",
            "}\n",
        );

        let stripped = strip_use_items(src_with_pub_use);

        // The pub use line should be removed entirely
        assert!(
            !stripped.contains("pub use"),
            "pub use import should be stripped: {stripped:?}"
        );
        // TEST_CONSTANT should no longer appear in the stripped source
        assert!(
            !stripped.contains("TEST_CONSTANT"),
            "identifier in pub use should not appear after stripping: {stripped:?}"
        );
        // But REAL_CONSTANT should still appear
        assert!(
            stripped.contains("REAL_CONSTANT"),
            "real constant declaration should remain: {stripped:?}"
        );
        // And the builder referencing it should remain
        assert!(
            stripped.contains("builder()"),
            "function calling the constant should remain: {stripped:?}"
        );

        // Test pub(crate) use variant
        let src_with_pub_crate_use = r#"pub(crate) use super::{ANOTHER_CONSTANT};"#;
        let stripped_crate = strip_use_items(src_with_pub_crate_use);
        assert!(
            !stripped_crate.contains("ANOTHER_CONSTANT"),
            "identifier in pub(crate) use should be stripped"
        );

        // Test pub(super) use variant
        let src_with_pub_super_use = r#"pub(super) use crate::rewards::{YET_ANOTHER};"#;
        let stripped_super = strip_use_items(src_with_pub_super_use);
        assert!(
            !stripped_super.contains("YET_ANOTHER"),
            "identifier in pub(super) use should be stripped"
        );

        // Test pub(in ...) use variant
        let src_with_pub_in_use = r#"pub(in super::module) use crate::rewards::{FINAL_ONE};"#;
        let stripped_in = strip_use_items(src_with_pub_in_use);
        assert!(
            !stripped_in.contains("FINAL_ONE"),
            "identifier in pub(in ...) use should be stripped"
        );
    }

    /// Every `pub`/`pub(crate)`/`pub(super)` `... : Msg = Msg::new(...)` constant name declared in
    /// `src` -- a line-level scan, deliberately not a full parser, matching this crate's existing
    /// `test_scan` house style of explicit, narrow source scans over full syntax trees.
    ///
    /// Deliberately does NOT match on the contiguous bytes `Msg` immediately followed by
    /// `::new(` immediately followed by a quote mark: `i18n::tests`'s own
    /// `every_locale_carries_every_key_and_no_more` guard text-scans every `.rs` file under `src`
    /// for that joined sequence to build its key set, and would misparse a single string literal
    /// spelling it out as a real call site -- eating everything up to this file's next quote mark
    /// as one giant fake key. Splitting the check across two non-adjacent literals keeps this
    /// detector's own source bytes out of that scanner's needle.
    fn declared_msg_constant_names(src: &str) -> Vec<&str> {
        src.lines()
            .filter_map(|line| {
                let trimmed = line.trim_start();
                let after_pub = trimmed
                    .strip_prefix("pub const ")
                    .or_else(|| trimmed.strip_prefix("pub(super) const "))
                    .or_else(|| trimmed.strip_prefix("pub(crate) const "))?;
                let (name, rest) = after_pub.split_once(':')?;
                let is_msg_decl =
                    rest.trim_start().starts_with("Msg = Msg") && rest.contains("::new(");
                is_msg_decl.then(|| name.trim())
            })
            .collect()
    }

    /// Removes EVERY `#[cfg(PREDICATE)] mod {name} { ... }` (or any other item) block from `src`
    /// whose PREDICATE names `test` as a term -- however many there are, whatever each is named,
    /// whatever the predicate's exact spelling -- leaving the rest of the file's production code
    /// intact and in place. Unlike a naive "cut from the first `#[cfg(test)]` to EOF", this
    /// tolerates production code that follows a test module in the same file.
    ///
    /// This replaces an earlier version that matched the single literal string `"#[cfg(test)]"`:
    /// it missed `#[cfg(all(test, unix))]` and any other predicate that merely CONTAINS `test`
    /// alongside another condition (dig_ecosystem#3331) -- the same enumeration-of-spellings shape
    /// this doc already once named as the dig_ecosystem#3315 defect (an enumerated list of MODULE
    /// names, not attribute spellings, but the identical failure: an enumeration can only check
    /// the enumeration it lists). A second attempt at the fix ([`cfg_predicate_marks_test`]) was
    /// itself still an enumeration -- "contains the word `test`, except the one literal spelling
    /// `not(test)`" -- so it mis-stripped genuine production code like
    /// `#[cfg(all(not(test), unix))]` (true only OUTSIDE test, on unix) and
    /// `#[cfg(any(not(test), unix))]` (true in nearly every real build). Neither a list of
    /// spellings nor one carve-out from it can be correct for an open-ended predicate grammar.
    ///
    /// The actual fix parses the predicate into `not`/`all`/`any` combinators over atoms and
    /// evaluates it with three-valued (Kleene) logic: the atom `test` is definitely FALSE (this
    /// asks what a production build does), and every other atom (`unix`, `feature = "x"`, an
    /// identifier nobody has spelled yet) is UNKNOWN, because it may hold in a real build. A
    /// block is stripped if and only if its predicate evaluates to definitely FALSE; UNKNOWN
    /// means "might compile in production" and is kept. That is the fail-safe direction: wrongly
    /// keeping a test module is a nuisance, wrongly deleting production code is silent corruption
    /// of what the sole-caller scan considers reachable. A predicate that fails to parse is also
    /// treated as UNKNOWN (kept), for the same reason.
    ///
    /// Comment lines are stripped FIRST, via the shared `test_scan::strip_comment_lines` (PR #419
    /// review): a doc comment that merely QUOTES the literal text `#[cfg(test)]` in prose -- this
    /// very file's own doc comments do that -- must not be mistaken by
    /// [`next_cfg_attr_marking_test`]'s raw byte scan for a real attribute; `remove_brace_block`'s
    /// brace depth-count is not comment-aware either, so it would then delete whatever unrelated
    /// brace-delimited item came next (the same incident class that once truncated this file
    /// from 53654 to 5345 bytes, dig_ecosystem#3367 review round 2).
    fn strip_all_test_mods(src: &str) -> String {
        let mut result = strip_comment_lines(src);
        while let Some(pos) = next_cfg_attr_marking_test(&result, 0) {
            result = remove_brace_block(&result, pos);
        }
        result
    }

    /// Finds the next `#[cfg(...)]` attribute at or after `from` whose predicate marks the item
    /// below it as test-only (see [`cfg_predicate_marks_test`]), skipping over any `#[cfg(...)]`
    /// attribute that does not. Returns the byte offset of the attribute's own `#`, so the caller
    /// can hand it straight to [`remove_brace_block`].
    fn next_cfg_attr_marking_test(src: &str, mut from: usize) -> Option<usize> {
        loop {
            let rel = src[from..].find("#[cfg(")?;
            let start = from + rel;
            let (predicate, end) = cfg_predicate_at(src, start)?;
            if cfg_predicate_marks_test(&predicate) {
                return Some(start);
            }
            from = end;
        }
    }

    /// Extracts the parenthesized predicate text of a `#[cfg(...)]` attribute starting at byte
    /// offset `attr_start` (the position of its own `#`), depth-counting parens so a nested
    /// predicate like `all(test, unix)` or `any(not(test), feature = "x")` is captured whole
    /// rather than cut at the first inner `)`. Returns the predicate text and the byte offset one
    /// past the attribute's closing paren.
    fn cfg_predicate_at(src: &str, attr_start: usize) -> Option<(String, usize)> {
        let open_paren = attr_start + src[attr_start..].find('(')?;
        let mut depth = 0i32;
        let mut end = None;
        for (i, ch) in src[open_paren..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open_paren + i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end?;
        Some((src[open_paren + 1..end - 1].to_string(), end))
    }

    /// Three-valued (Kleene) truth of a `#[cfg(...)]` predicate, asking "does this hold in a
    /// production (non-test) build". `test` is definitely [`Tri::False`]; every other atom is
    /// [`Tri::Unknown`] (it may hold in some real build); `not`/`all`/`any` combine per standard
    /// Kleene semantics. See [`strip_all_test_mods`]'s doc for why this replaced an enumeration
    /// of predicate spellings.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Tri {
        True,
        False,
        Unknown,
    }

    impl Tri {
        fn negate(self) -> Tri {
            match self {
                Tri::True => Tri::False,
                Tri::False => Tri::True,
                Tri::Unknown => Tri::Unknown,
            }
        }
    }

    /// Kleene AND: false if any operand is false, true if every operand is true, else unknown.
    fn tri_all(vals: impl Iterator<Item = Tri>) -> Tri {
        let mut all_true = true;
        for v in vals {
            match v {
                Tri::False => return Tri::False,
                Tri::Unknown => all_true = false,
                Tri::True => {}
            }
        }
        if all_true {
            Tri::True
        } else {
            Tri::Unknown
        }
    }

    /// Kleene OR: true if any operand is true, false if every operand is false, else unknown.
    fn tri_any(vals: impl Iterator<Item = Tri>) -> Tri {
        let mut all_false = true;
        for v in vals {
            match v {
                Tri::True => return Tri::True,
                Tri::Unknown => all_false = false,
                Tri::False => {}
            }
        }
        if all_false {
            Tri::False
        } else {
            Tri::Unknown
        }
    }

    /// If `p` is exactly `"<call_prefix>...)"` with the parens balanced end-to-end (not, e.g., a
    /// top-level list like `"not(test), unix"` that merely starts with the prefix), returns the
    /// inner text between the call's own opening and closing parens. `call_prefix` includes the
    /// trailing `(`, e.g. `"not("`.
    fn strip_call<'a>(p: &'a str, call_prefix: &str) -> Option<&'a str> {
        let rest = p.strip_prefix(call_prefix)?;
        let inner = rest.strip_suffix(')')?;
        let mut depth = 0i32;
        for ch in inner.chars() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth < 0 {
                        return None;
                    }
                }
                _ => {}
            }
        }
        if depth == 0 {
            Some(inner)
        } else {
            None
        }
    }

    /// Splits `inner` on commas at paren-depth zero, so `all(any(test, unix), test)`'s outer
    /// `all(...)` splits into `["any(test, unix)", "test"]`, not four fragments.
    ///
    /// Quote-aware (PR #419 review): a comma sitting INSIDE a `"..."` string literal -- e.g.
    /// `feature = "a,test,b"` -- is not a separator. Before this fix, `all(unix, feature =
    /// "a,test,b")` split into `["unix", "feature = \"a", "test", "b\")"]`, manufacturing a
    /// fragment exactly equal to the atom `test`; [`eval_cfg_predicate`] then read that fragment
    /// as the real `test` atom, forcing a definite-FALSE verdict and wrongly stripping genuine
    /// production code gated on that feature string -- the wrongful-strip direction this whole
    /// evaluator exists to close. A `\"` inside the string does not end it.
    fn split_top_level_commas(inner: &str) -> Vec<&str> {
        let mut parts = Vec::new();
        let mut depth = 0i32;
        let mut in_string = false;
        let mut start = 0;
        let mut chars = inner.char_indices().peekable();
        while let Some((i, ch)) = chars.next() {
            if in_string {
                match ch {
                    '\\' => {
                        // An escaped character (`\"`, `\\`, ...) never ends the string; consume
                        // it here so the following char is never re-examined as a delimiter.
                        chars.next();
                    }
                    '"' => in_string = false,
                    _ => {}
                }
                continue;
            }
            match ch {
                '"' => in_string = true,
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => {
                    parts.push(inner[start..i].trim());
                    start = i + ch.len_utf8();
                }
                _ => {}
            }
        }
        parts.push(inner[start..].trim());
        parts
    }

    /// Evaluates a `#[cfg(...)]` predicate's text (the content between its own outer parens) to
    /// three-valued truth. An atom other than the bare identifier `test` -- `unix`,
    /// `feature = "x"`, anything unrecognized -- is [`Tri::Unknown`], never assumed false or
    /// true. A predicate this parser cannot make sense of also evaluates to [`Tri::Unknown`]
    /// (fail-safe: keep it).
    fn eval_cfg_predicate(p: &str) -> Tri {
        let p = p.trim();
        if p == "test" {
            return Tri::False;
        }
        if let Some(inner) = strip_call(p, "not(") {
            return eval_cfg_predicate(inner).negate();
        }
        if let Some(inner) = strip_call(p, "all(") {
            return tri_all(
                split_top_level_commas(inner)
                    .into_iter()
                    .map(eval_cfg_predicate),
            );
        }
        if let Some(inner) = strip_call(p, "any(") {
            return tri_any(
                split_top_level_commas(inner)
                    .into_iter()
                    .map(eval_cfg_predicate),
            );
        }
        Tri::Unknown
    }

    /// True if a `#[cfg(...)]` predicate is definitely FALSE in a production build -- the only
    /// condition under which [`strip_all_test_mods`] removes the item below it. See
    /// [`eval_cfg_predicate`] for the three-valued evaluation this delegates to, and
    /// [`strip_all_test_mods`]'s doc for why "definitely false", not "mentions `test`", is the
    /// right predicate.
    fn cfg_predicate_marks_test(predicate: &str) -> bool {
        eval_cfg_predicate(predicate) == Tri::False
    }

    /// Regression for dig_ecosystem#3315: `strip_test_mod`'s predecessor took an enumerated list
    /// of module names (`rewards_sections_tests`, `creation_gate_tests`) and missed `pane.rs`'s
    /// THIRD, plain `#[cfg(test)] mod tests` -- so a `Msg` constant named only from inside that
    /// module read as "referenced by production" to `every_msg_constant_is_reachable_outside_test_code`,
    /// the exact defect class the guard exists to catch. This fixture reproduces that shape
    /// directly (a plain, unnamed-in-any-enumeration `mod tests` sitting after real production
    /// code, exactly as it sits in `pane.rs`) and proves `strip_all_test_mods` -- not an
    /// enumeration -- removes it, so the constant it alone names correctly reads as UNREACHABLE.
    #[test]
    fn constant_referenced_only_from_a_plain_cfg_test_mod_tests_is_unreachable() {
        // The literal is split with concat!() so every_msg_key_in_source() (i18n/tests.rs) does
        // not mistake this guard fixture for a product key; rejoining it would turn the parity
        // test red and hide that the guard is exercising the right surface.
        const FIXTURE_SOURCE: &str = concat!(
            "fn real_builder() {\n",
            "    let _ = REAL_KEY_IN_PRODUCTION;\n",
            "}\n",
            "\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    use super::*;\n",
            "\n",
            "    #[test]\n",
            "    fn some_test() {\n",
            "        let _ = KEY_ONLY_IN_PLAIN_TEST_MOD;\n",
            "    }\n",
            "}\n",
        );

        let stripped = strip_all_test_mods(FIXTURE_SOURCE);

        assert!(
            !stripped.contains("mod tests"),
            "the plain, unnamed-in-any-enumeration `mod tests` block must be fully removed: \
             {stripped:?}"
        );
        assert!(
            stripped.contains("real_builder"),
            "production code before the test module must survive: {stripped:?}"
        );

        let production = harden_production_text(&stripped);
        assert!(
            contains_word(&production, "REAL_KEY_IN_PRODUCTION"),
            "a key named by real production code must stay reachable"
        );
        assert!(
            !contains_word(&production, "KEY_ONLY_IN_PLAIN_TEST_MOD"),
            "a key named ONLY inside a plain `#[cfg(test)] mod tests` must NOT read as reachable \
             -- this is the exact false-negative dig_ecosystem#3315 found"
        );
    }

    /// Regression for dig_ecosystem#3331: `strip_all_test_mods`'s marker used to be the single
    /// literal string `"#[cfg(test)]"`, so `#[cfg(all(test, unix))]` (or any other predicate that
    /// merely CONTAINS `test`, such as `#[cfg(all(test, feature = "x"))]`) was left un-stripped --
    /// a `Msg` constant referenced only from such a module read as "referenced by production" to
    /// `every_msg_constant_is_reachable_outside_test_code`, the same enumeration-of-spellings shape
    /// this file's own doc on `strip_all_test_mods` already names as the dig_ecosystem#3315
    /// defect. This fixture reproduces the `all(test, unix)` shape and proves the generalized,
    /// structural cfg-predicate scan -- not a second literal added to a list -- strips it.
    #[test]
    fn strip_all_test_mods_strips_cfg_all_test_unix() {
        // The literal is split with concat!() so every_msg_key_in_source() (i18n/tests.rs) does
        // not mistake this guard fixture for a product key; rejoining it would turn the parity
        // test red and hide that the guard is exercising the right surface.
        const FIXTURE_SOURCE: &str = concat!(
            "fn real_builder() {\n",
            "    let _ = REAL_KEY_BEFORE_CFG_ALL_TEST_UNIX;\n",
            "}\n",
            "\n",
            "#[cfg(all(test, unix))]\n",
            "mod unix_only_tests {\n",
            "    #[test]\n",
            "    fn some_test() {\n",
            "        let _ = KEY_ONLY_IN_CFG_ALL_TEST_UNIX;\n",
            "    }\n",
            "}\n",
        );

        let stripped = strip_all_test_mods(FIXTURE_SOURCE);

        assert!(
            !stripped.contains("mod unix_only_tests"),
            "a #[cfg(all(test, unix))] test module must be fully removed: {stripped:?}"
        );
        assert!(
            stripped.contains("real_builder"),
            "production code before the test module must survive: {stripped:?}"
        );

        let production = harden_production_text(&stripped);
        assert!(
            contains_word(&production, "REAL_KEY_BEFORE_CFG_ALL_TEST_UNIX"),
            "a key named by real production code must stay reachable"
        );
        assert!(
            !contains_word(&production, "KEY_ONLY_IN_CFG_ALL_TEST_UNIX"),
            "a key named ONLY inside a #[cfg(all(test, unix))] module must NOT read as reachable"
        );
    }

    /// Regression for dig_ecosystem#3331: `#[cfg(not(test))]` marks PRODUCTION code (it is true
    /// exactly when NOT compiling for test), so it must never be stripped by
    /// `strip_all_test_mods` -- the opposite of `#[cfg(test)]`/`#[cfg(all(test, ..))]`, which are
    /// true only WHEN compiling for test. A scan that matched on the bare substring `"test"`
    /// would wrongly strip this too (the vault's rule: a substring assertion on an identifier is
    /// satisfied by its superstring, and `not(test)` contains the word `test`).
    #[test]
    fn strip_all_test_mods_keeps_cfg_not_test() {
        const FIXTURE_SOURCE: &str = concat!(
            "#[cfg(not(test))]\n",
            "fn production_only_builder() {\n",
            "    let _ = KEY_ONLY_IN_CFG_NOT_TEST;\n",
            "}\n",
        );

        let stripped = strip_all_test_mods(FIXTURE_SOURCE);

        assert!(
            stripped.contains("production_only_builder"),
            "#[cfg(not(test))] marks PRODUCTION code and must survive stripping: {stripped:?}"
        );
        assert!(
            contains_word(&stripped, "KEY_ONLY_IN_CFG_NOT_TEST"),
            "a key named only inside #[cfg(not(test))] must remain reachable: {stripped:?}"
        );
    }

    /// Regression: the finding on PR #419's review (discussion r4113816042) against
    /// `cfg_predicate_marks_test`'s enumeration-plus-one-carve-out formulation. `unix` here is
    /// UNKNOWN (it may or may not hold in a real build), so `all(not(test), unix)` is true only
    /// outside test on unix -- genuine PRODUCTION code, true in a real, non-test unix build -- and
    /// must never be stripped. The old code checked "contains the word `test`, unless the whole
    /// predicate is exactly `not(test)`" and so mis-classified this as test-only and deleted it.
    #[test]
    fn strip_all_test_mods_keeps_cfg_all_not_test_unix() {
        const FIXTURE_SOURCE: &str = concat!(
            "#[cfg(all(not(test), unix))]\n",
            "fn production_unix_only_builder() {\n",
            "    let _ = KEY_ONLY_IN_CFG_ALL_NOT_TEST_UNIX;\n",
            "}\n",
        );

        let stripped = strip_all_test_mods(FIXTURE_SOURCE);

        assert!(
            stripped.contains("production_unix_only_builder"),
            "#[cfg(all(not(test), unix))] is genuine production code (true only outside test, on \
             unix) and must survive stripping: {stripped:?}"
        );
        assert!(
            contains_word(&stripped, "KEY_ONLY_IN_CFG_ALL_NOT_TEST_UNIX"),
            "a key named only inside #[cfg(all(not(test), unix))] must remain reachable: \
             {stripped:?}"
        );
    }

    /// Table-driven coverage of [`cfg_predicate_marks_test`] (equivalently,
    /// [`eval_cfg_predicate`]) against every shape named in dig_ecosystem PR #419's review
    /// (discussion r4113816042), spelling out the three-valued evaluation directly rather than
    /// re-deriving it from an enumeration of predicate strings.
    #[test]
    fn cfg_predicate_marks_test_table() {
        let cases: &[(&str, bool)] = &[
            ("test", true),
            ("all(test, unix)", true),
            ("all(test, feature = \"x\")", true),
            ("not(test)", false),
            ("all(not(test), unix)", false),
            ("any(not(test), unix)", false),
            ("any(test, unix)", false),
            ("not(all(test, unix))", false),
            ("all(any(test, unix), test)", true),
        ];
        for (predicate, expect_strip) in cases {
            assert_eq!(
                cfg_predicate_marks_test(predicate),
                *expect_strip,
                "predicate {predicate:?} expected marks_test={expect_strip}"
            );
        }
    }

    /// A predicate this parser cannot make sense of must evaluate UNKNOWN, not FALSE -- the
    /// fail-safe direction, since wrongly stripping is silent production-code deletion while
    /// wrongly keeping is only a nuisance.
    #[test]
    fn cfg_predicate_marks_test_keeps_unparseable_predicate() {
        for malformed in ["all(test", "not test)", "all(test))", ""] {
            assert!(
                !cfg_predicate_marks_test(malformed),
                "malformed predicate {malformed:?} must fail safe (keep, not strip)"
            );
        }
    }

    /// Regression: `next_cfg_attr_marking_test` used to scan `src`'s raw bytes for the literal
    /// `#[cfg(` with no comment stripping first -- the same incident class that once truncated
    /// this very file from 53654 to 5345 bytes (dig_ecosystem#3367 review round 2). A doc comment
    /// that merely QUOTES `#[cfg(test)]` in prose (this file does exactly that, e.g. above
    /// [`strip_all_test_mods`]) would be matched as if it were a real attribute, and
    /// `remove_brace_block`'s depth-count -- not comment-aware either -- would then delete the
    /// NEXT unrelated brace-delimited item in the file instead of the real test module. Comments
    /// must be stripped before the scan ever runs.
    #[test]
    fn a_doc_comment_quoting_the_marker_does_not_delete_the_next_unrelated_item() {
        const FIXTURE_SOURCE: &str = concat!(
            "/// Gated on `#[cfg(test)]`, purely as prose describing a SIBLING module -- this\n",
            "/// comment names no real attribute of its own.\n",
            "pub const KEPT_BEFORE_THE_MENTION: &str = \"before\";\n",
            "\n",
            "pub fn real_unrelated_builder() {\n",
            "    let _ = REAL_KEY_AFTER_COMMENT_MENTION;\n",
            "}\n",
            "\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    #[test]\n",
            "    fn some_test() {\n",
            "        let _ = KEY_ONLY_IN_REAL_TEST_MOD;\n",
            "    }\n",
            "}\n",
        );

        let stripped = strip_all_test_mods(FIXTURE_SOURCE);

        assert!(
            !stripped.contains("mod tests"),
            "the real #[cfg(test)] mod tests block must still be removed: {stripped:?}"
        );
        assert!(
            stripped.contains("KEPT_BEFORE_THE_MENTION"),
            "production code before the doc-comment mention must survive: {stripped:?}"
        );
        assert!(
            stripped.contains("real_unrelated_builder"),
            "the unrelated production item AFTER the doc-comment mention must survive -- a \
             comment-blind scan deletes exactly this: {stripped:?}"
        );

        let production = harden_production_text(&stripped);
        assert!(
            contains_word(&production, "REAL_KEY_AFTER_COMMENT_MENTION"),
            "a key named only by the unrelated builder must stay reachable: {production:?}"
        );
        assert!(
            !contains_word(&production, "KEY_ONLY_IN_REAL_TEST_MOD"),
            "a key named only inside the real test module must still read as unreachable"
        );
    }

    /// Regression: `split_top_level_commas` used to split on every comma at paren-depth zero,
    /// including a comma sitting INSIDE a quoted string -- so
    /// `all(unix, feature = "a,test,b")` produced a bogus fragment exactly equal to `test`, which
    /// `eval_cfg_predicate` then read as the real `test` atom, forcing a definite-FALSE verdict
    /// and wrongly stripping genuine production code gated on that feature string. A comma
    /// inside a string literal is not a separator.
    #[test]
    fn split_top_level_commas_is_quote_aware() {
        for predicate in [
            r#"all(unix, feature = "a,test,b")"#,
            r#"all(unix, feature = ",test,")"#,
        ] {
            assert!(
                !cfg_predicate_marks_test(predicate),
                "predicate {predicate:?} must evaluate UNKNOWN (kept) -- the comma inside its \
                 quoted feature string is not a real separator"
            );
        }
    }

    /// From `item_start` (the byte offset of an item's own attribute or keyword), finds that
    /// item's brace-delimited body by depth-counting `{`/`}` from its first opening brace, and
    /// returns `src` with the whole item (attribute line through matching `}`) removed.
    ///
    /// String and char literals are skipped, not depth-counted: a `"{"` string or a `'{'`/`'}'`
    /// char literal (this crate's own test helpers depth-count braces the same way
    /// `remove_brace_block` does, so `create_card.rs`'s test module contains exactly this shape)
    /// must not be mistaken for a real delimiter. This was raised non-blocking in PR #419's
    /// review on its own, but making [`strip_all_test_mods`] strip comments first (the Finding 1
    /// fix) exposed it as a real panic: doc-comment prose that happened to quote a `` ` ``-`{`/`}`
    /// pair used to numerically cancel out these char literals in the raw, un-stripped scan;
    /// once those comment braces are gone, the char literals' textual imbalance is real. A
    /// lifetime (`'a`, `'static`) is NOT a char literal (no matching closing `'`) and is left
    /// alone.
    fn remove_brace_block(src: &str, item_start: usize) -> String {
        let open = item_start + src[item_start..].find('{').expect("item has no `{` body");
        let mut depth = 0i32;
        let mut in_string = false;
        let mut end = None;
        let mut i = open;
        while i < src.len() {
            let ch = src[i..].chars().next().expect("valid char boundary");
            let ch_len = ch.len_utf8();
            if in_string {
                match ch {
                    '\\' => i += ch_len + next_char_len(src, i + ch_len),
                    '"' => {
                        in_string = false;
                        i += ch_len;
                    }
                    _ => i += ch_len,
                }
                continue;
            }
            match ch {
                '"' => {
                    in_string = true;
                    i += ch_len;
                }
                '\'' if is_char_literal_at(src, i) => {
                    i = char_literal_end(src, i);
                }
                '{' => {
                    depth += 1;
                    i += ch_len;
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i + ch_len);
                        break;
                    }
                    i += ch_len;
                }
                _ => i += ch_len,
            }
        }
        let end = end.expect("unbalanced braces in test module");
        format!("{}{}", &src[..item_start], &src[end..])
    }

    /// The byte length of the char starting at `at` in `src`, or `1` past end-of-string (never
    /// dereferenced -- callers only use this to step an index past an escape's argument).
    fn next_char_len(src: &str, at: usize) -> usize {
        src[at..].chars().next().map(char::len_utf8).unwrap_or(1)
    }

    /// True if `src[at..]` (which starts with `'`) opens a Rust CHAR LITERAL (`'{'`, `'\\'`,
    /// `'\u{7B}'`, ...) rather than a LIFETIME (`'a`, `'static`, ...) -- the two share the single
    /// leading `'` but only a char literal closes with a matching `'`. Needed so
    /// [`remove_brace_block`]'s brace depth-count does not miscount a `{`/`}` written as a char
    /// literal (real code in this crate's own test helpers depth-counts braces the same way) as
    /// a real delimiter, while never swallowing a lifetime's generic parameter as if it were one.
    fn is_char_literal_at(src: &str, at: usize) -> bool {
        char_literal_end_inner(src, at).is_some()
    }

    /// The index just past a char literal starting at `at`, or `at + 1` (treating the `'` as an
    /// ordinary, un-skipped character -- a lifetime) if `src[at..]` is not one.
    fn char_literal_end(src: &str, at: usize) -> usize {
        char_literal_end_inner(src, at).unwrap_or(at + 1)
    }

    fn char_literal_end_inner(src: &str, at: usize) -> Option<usize> {
        let rest = &src[at..];
        let mut chars = rest.char_indices();
        let (_, quote) = chars.next()?;
        debug_assert_eq!(quote, '\'');
        let (i1, c1) = chars.next()?;
        if c1 == '\\' {
            // An escape sequence: consume its argument char (`\n`, `\'`, ...) or, for `\u{..}`,
            // everything up to and including its closing `}` before looking for the literal's
            // own closing `'`.
            let (i2, c2) = chars.next()?;
            let after_escape = if c2 == 'u' {
                let brace_rel = rest[i2..].find('{')?;
                let close_rel = rest[i2 + brace_rel..].find('}')?;
                i2 + brace_rel + close_rel + 1
            } else {
                i2 + c2.len_utf8()
            };
            if rest[after_escape..].starts_with('\'') {
                return Some(at + after_escape + 1);
            }
            return None;
        }
        let after_first = i1 + c1.len_utf8();
        if rest[after_first..].starts_with('\'') {
            return Some(at + after_first + 1);
        }
        None
    }

    /// True if `word` appears in `haystack` as a whole identifier -- never as a substring of a
    /// longer name (so e.g. `STATUS_LIVE` cannot false-match inside a hypothetical
    /// `STATUS_LIVE_DETAIL`).
    fn contains_word(haystack: &str, word: &str) -> bool {
        let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let bytes = haystack.as_bytes();
        let mut start = 0;
        while let Some(pos) = haystack[start..].find(word) {
            let idx = start + pos;
            let before_ok = idx == 0 || !is_ident(bytes[idx - 1]);
            let after = idx + word.len();
            let after_ok = after >= bytes.len() || !is_ident(bytes[after]);
            if before_ok && after_ok {
                return true;
            }
            start = idx + 1;
        }
        false
    }
}
