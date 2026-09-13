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

// ---------------------------------------------------------------------------------------------
// dig_ecosystem#3253's correctness-gate fix: [`super::pane`]'s sentence builders routed to this
// catalog (they shipped hardcoded English in the same PR that added the keys above). These seven
// are the facts that had no existing key to route to; everything else in `pane.rs` reuses a key
// already defined above.
// ---------------------------------------------------------------------------------------------

/// [`super::reading::ProverReading::Live`] — the one prover state with nothing wrong to report.
pub const STATUS_LIVE: Msg = Msg::new("rewards-status-live");
/// [`super::reading::EntrySetReading::Known`]. Placeables: `entry_count`, `last_entry_write_at`
/// (a raw unix-time integer — dig-app-core has no date-formatting helper yet; tracked separately).
pub const ENTRY_SET_KNOWN: Msg = Msg::new("rewards-entry-set-known");
/// [`super::reading::PayoutReading::Paid`]. Placeables: `amount` (already through
/// [`crate::amount::amount_with_unit`], never a raw integer) and `last_cycle_completed_at` (a raw
/// unix-time integer, same caveat as [`ENTRY_SET_KNOWN`]).
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
    STATUS_LIVE,
    ENTRY_SET_KNOWN,
    PAID_OUT_TOTAL,
    CADENCE_NO_MIRRORS_YET,
    CADENCE_NO_FUNDING_RATE,
    CADENCE_SUB_DAY_FLOOR,
    CADENCE_FAR_END,
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

    /// Keys this guard does NOT enforce yet, each for a reason already on record elsewhere in
    /// this crate -- not a workaround, a transcription of a gap this ticket does not own:
    ///
    /// - The five warning blocks + heading + closing line: `pane.rs`'s own doc on
    ///   `REQUIRED_WARNING_KEYS` says the paint step is "deferred to the commit that paints the
    ///   five blocks" -- the acknowledgement gate ([`super::pane::WarningsShown`]) shipped, the
    ///   rendering did not, and this ticket's HARD LIMITS forbid touching `WarningsShown`/
    ///   `CreationGate`.
    /// - The five donation keys: `mod.rs`'s doc lists the donation control itself as not built in
    ///   this pass ("No create, refill or clawback control is built here").
    /// - `ENTRY_SET_STALE`: a genuine instance of the SAME defect class this guard exists to
    ///   catch -- [`super::reading::EntrySetReading`] has only `NeverWritten`/`Known` variants, no
    ///   `Stale`, so this key can never be selected by any match arm. Found BY this guard while
    ///   writing it; out of scope for dig_ecosystem#3253's B-plain removal (which names eight
    ///   specific keys, not this one) and reported rather than fixed here.
    const NOT_YET_ENFORCED: &[&str] = &[
        "WARNING_HEADING",
        "WARNING_BLOCK_1",
        "WARNING_BLOCK_2",
        "WARNING_BLOCK_3",
        "WARNING_BLOCK_4",
        "WARNING_BLOCK_5",
        "WARNING_CLOSING",
        "DONATION_LABEL",
        "DONATION_BODY",
        "DONATION_CONFIRM_LAST_LINE",
        "DONATION_CONFIRM_BUTTON",
        "DONATION_CANCEL_BUTTON",
        "ENTRY_SET_STALE",
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
    #[test]
    fn every_msg_constant_is_reachable_outside_test_code() {
        // Production text of THIS file: everything before its own `#[cfg(test)]` tail (`ALL_KEYS`
        // onward), which never counts as a "reference" -- it exists only so these tests can
        // iterate every key, not because any of them renders a sentence.
        let copy_production = include_str!("copy.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("copy.rs always has a #[cfg(test)] section");

        let pane_production = strip_test_mod(
            &strip_test_mod(include_str!("pane.rs"), "rewards_sections_tests"),
            "creation_gate_tests",
        );
        let clawback_production = strip_test_mod(include_str!("clawback.rs"), "tests");
        let production = harden_production_text(&format!("{pane_production}{clawback_production}"));

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

    /// Runs every text-level hatch-closer over a production source blob, in the order that
    /// matters: dead-code-allowed item bodies come out whole (so a builder's own `use`-free
    /// argument names inside it don't leak back in as false references once the body is gone),
    /// then `use` items, then comment lines. Two adversarial-gate findings live here:
    /// - a constant named only in a `use { ... }` import list reads as "referenced from
    ///   production" to a plain `contains_word` scan, even though nothing ever calls `.with(...)`
    ///   on it (dig_ecosystem#3253 finding 2);
    /// - a `pub(crate)` builder marked `#[allow(dead_code)]` is, by definition, code the compiler
    ///   would otherwise have flagged as unreachable from any real call site; naming a key only
    ///   inside such a builder is the same unreachability the whole guard exists to catch, not an
    ///   exemption from it (finding 3).
    fn harden_production_text(src: &str) -> String {
        strip_comment_lines(&strip_use_items(&strip_dead_code_allowed_items(src)))
    }

    /// Removes every item (attribute line through its matching closing brace) that carries an
    /// `#[allow(dead_code)]` attribute directly above it. A builder silenced this way is a
    /// text-scannable proxy for "the compiler would have told you this is unreachable and we
    /// silenced it" -- a `Msg` constant named only inside one is not reachable from production,
    /// no matter how plausible the builder's own doc comment reads.
    fn strip_dead_code_allowed_items(src: &str) -> String {
        let marker = "#[allow(dead_code)]";
        let mut result = src.to_string();
        while let Some(pos) = result.find(marker) {
            result = remove_brace_block(&result, pos);
        }
        result
    }

    /// Removes every `use ...;` item, including ones whose braced list spans multiple lines. A
    /// constant named only inside a `use super::copy::{...}` list is imported, not referenced --
    /// nothing downstream of the import calls `.with(...)` on it -- so it must not count as a
    /// production reference just because the identifier appears in the source text.
    fn strip_use_items(src: &str) -> String {
        let mut out = String::new();
        let mut skipping = false;
        for line in src.lines() {
            if !skipping && line.trim_start().starts_with("use ") {
                skipping = true;
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

    /// Drops every line whose first non-whitespace characters are `//` (plain, `///` or `//!`) --
    /// a `Msg` constant's name appearing only inside a doc comment (e.g. "`WARNING_BLOCK_1`
    /// through `_5`") must not count as a production reference; only real code naming the
    /// constant does.
    fn strip_comment_lines(src: &str) -> String {
        src.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
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

    /// Removes one `#[cfg(test)] mod {mod_name} { ... }` block (attribute through its matching
    /// closing brace) from `src`, leaving the rest of the file's production code intact and in
    /// place -- unlike a naive "cut from the first `#[cfg(test)]` to EOF", this tolerates
    /// production code that follows a test module in the same file (as `pane.rs` does, between
    /// its two test modules).
    fn strip_test_mod(src: &str, mod_name: &str) -> String {
        let marker = format!("#[cfg(test)]\nmod {mod_name}");
        let Some(start) = src.find(&marker) else {
            // Not present (e.g. clawback.rs's mod is literally named `tests`) -- try the bare
            // `mod NAME {` form without requiring the attribute immediately above it.
            let bare = format!("mod {mod_name}");
            let Some(mod_pos) = src.find(&bare) else {
                panic!("{mod_name} not found in source -- this guard's markers are stale");
            };
            return remove_brace_block(src, mod_pos);
        };
        remove_brace_block(src, start)
    }

    /// From `item_start` (the byte offset of an item's own attribute or keyword), finds that
    /// item's brace-delimited body by depth-counting `{`/`}` from its first opening brace, and
    /// returns `src` with the whole item (attribute line through matching `}`) removed.
    fn remove_brace_block(src: &str, item_start: usize) -> String {
        let open = item_start + src[item_start..].find('{').expect("item has no `{` body");
        let mut depth = 0i32;
        let mut end = None;
        for (i, ch) in src[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.expect("unbalanced braces in test module");
        format!("{}{}", &src[..item_start], &src[end..])
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
