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
pub const CLAWBACK_CONFIRM_TITLE: Msg = Msg::new("rewards-clawback-confirm-title");
/// Placeables: `slot_amount`, `epoch_index`, `epoch_start_date`, `returned_amount`,
/// `forfeited_amount`, `clawback_ph_short`. Every value MUST come from the parsed commitment slot,
/// never from pane state (DECISIONS Q3: "the confirm window reads NOTHING from the pane's state").
pub const CLAWBACK_CONFIRM_BODY: Msg = Msg::new("rewards-clawback-confirm-body");
/// Placeable: `returned_amount` — the approving click names the amount.
pub const CLAWBACK_WITHDRAW_BUTTON: Msg = Msg::new("rewards-clawback-withdraw-button");
pub const CLAWBACK_KEEP_BUTTON: Msg = Msg::new("rewards-clawback-keep-button");

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
/// SPEC §2.4 clause 3 / [`super::reading::EntrySetReading::NeverWritten`].
pub const STATUS_ENTRY_COUNT_UNKNOWN: Msg = Msg::new("rewards-status-entry-count-unknown");
/// [`super::reading::ProverReading::ClockUnusable`] — DECISIONS Q4.2, must never render as fresh.
pub const STATUS_CLOCK_UNUSABLE: Msg = Msg::new("rewards-status-clock-unusable");
/// [`super::reading::ProverReading::HeartbeatLate`]. Placeable: `minutes`.
pub const STATUS_HEARTBEAT_LATE: Msg = Msg::new("rewards-status-heartbeat-late");
/// [`super::reading::ProverReading::HeartbeatLost`]. Placeables: `duration`, `observed_at_date`.
pub const STATUS_HEARTBEAT_LOST: Msg = Msg::new("rewards-status-heartbeat-lost");
/// [`super::reading::ProverReading::CycleOverdue`]. Placeables: `since_date`, `due_date`.
pub const STATUS_CYCLE_OVERDUE: Msg = Msg::new("rewards-status-cycle-overdue");
/// Placeables: `entry_count`, `last_entry_write_date`, `since_epoch`, `now_epoch`, `epoch_gap`.
pub const ENTRY_SET_STALE: Msg = Msg::new("rewards-entry-set-stale");
pub const ENTRY_SET_NEVER_WRITTEN: Msg = Msg::new("rewards-entry-set-never-written");
/// "Paid out: nothing yet — this prover has never completed a cycle." — never a bare `0.000 $DIG`.
pub const PAID_OUT_NOTHING_YET: Msg = Msg::new("rewards-paid-out-nothing-yet");

/// Every key this module defines, for the exhaustiveness/render/sweep tests below. Keeping this
/// list here (rather than re-deriving it per test) is the one place a new key must be added or the
/// tests that iterate "every rewards key" silently stop covering it.
pub const ALL_KEYS: &[Msg] = &[
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
    ENTRY_SET_STALE,
    ENTRY_SET_NEVER_WRITTEN,
    PAID_OUT_NOTHING_YET,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Args;

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
        assert_eq!(WARNING_CLOSING.text_in(crate::i18n::Language::En), WARNING_CLOSING_LINE_EN);
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
}
