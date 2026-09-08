//! Every sentence this pane shows a person, as one catalog per [`crate::i18n`]'s existing
//! mechanism (fluent `.ftl`, `Msg::new`) — dig-app already has an i18n layer; this module follows
//! it rather than inventing a second one.
//!
//! # Three keys carry PROVISIONAL text
//!
//! [`CREATE_WARNING_SUMMARY`], [`CLAWBACK_CONFIRM_SUMMARY`], and the staleness-state family under
//! [`STATE_LABEL`] are decided in parallel by loop-decider (Q1/Q3/Q4) and are NOT this lane's to
//! write final copy for — this is money-honesty-critical text the epic owner reads personally. The
//! real copy is a DATA-ONLY change to the 14 `.ftl` catalogs once relayed; nothing here should need
//! to change shape to receive it. Every catalog entry below is marked `PROVISIONAL` in its English
//! source so the gap is visible in the file, not just in this doc comment.
//!
//! The remaining keys ([`REFILL_CADENCE`], [`STATUS_NOT_DISTRIBUTING`], [`STATUS_NEVER_RAN`],
//! [`STATUS_ENTRY_COUNT_UNKNOWN`]) quote SPEC clauses that already state the required wording
//! (§6.5.1, §2.4), so they carry final text now.

use crate::i18n::Msg;

/// SPEC §2.2: the creation-time uptime warning. PROVISIONAL — final English is loop-decider Q1.
pub const CREATE_WARNING_SUMMARY: Msg = Msg::new("rewards-create-warning-summary");

/// SPEC §6.5.1's literal required sentence shape: "at this funding rate a mirror clears the claim
/// threshold every N days". Final text — the spec dictates the content, not the decider.
pub const REFILL_CADENCE: Msg = Msg::new("rewards-refill-cadence");

/// SPEC §7.4/§7.5: the clawback confirmation. PROVISIONAL — final English is loop-decider Q3.
pub const CLAWBACK_CONFIRM_SUMMARY: Msg = Msg::new("rewards-clawback-confirm-summary");

/// SPEC §2.4 clause 1: literal required rendering for an absent record.
pub const STATUS_NOT_DISTRIBUTING: Msg = Msg::new("rewards-status-not-distributing");

/// SPEC §2.4 clause 2: literal required rendering for a zero payout with no completed cycle.
pub const STATUS_NEVER_RAN: Msg = Msg::new("rewards-status-never-ran");

/// SPEC §2.4 clause 3: literal required rendering for an entry count with no write timestamp.
pub const STATUS_ENTRY_COUNT_UNKNOWN: Msg = Msg::new("rewards-status-entry-count-unknown");

#[cfg(test)]
mod tests {
    use super::*;

    /// A key exists and renders SOMETHING in the active (English, by default) language — this is
    /// not a content check, just that the wiring reaches the catalog at all. Content correctness is
    /// `i18n::tests`'s job crate-wide.
    #[test]
    fn every_copy_key_renders_in_the_active_language() {
        for msg in [
            CREATE_WARNING_SUMMARY,
            REFILL_CADENCE,
            CLAWBACK_CONFIRM_SUMMARY,
            STATUS_NOT_DISTRIBUTING,
            STATUS_NEVER_RAN,
            STATUS_ENTRY_COUNT_UNKNOWN,
        ] {
            assert!(!msg.text().is_empty(), "{} rendered empty", msg.key());
        }
    }
}
