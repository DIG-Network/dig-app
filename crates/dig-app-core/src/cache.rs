//! The node content-cache cap: the pure, headless-testable logic behind the tray's cache-size
//! control (dig_ecosystem#2002).
//!
//! The tray shell renders a control that shows how much of the node's on-disk content cache is in
//! use against its cap, and lets a person change the cap. Every decision that control makes —
//! formatting a byte count, parsing a typed value, rejecting an absurd one, and deciding whether a
//! new cap will EVICT already-cached content — lives here as a pure function so it is unit-tested
//! rather than trapped inside a platform event loop.
//!
//! # The cap is the node's, persisted through the node
//!
//! The cap is applied ONLY via the node's `control.cache.setCap` control method
//! ([`crate::gateway`] maps it, [`crate::control`] carries it). dig-app never writes the node's
//! `config.json` itself: the node holds a cross-process lock over that file, and a second writer
//! would race a concurrent node write and could corrupt it. So this module owns the *logic* and the
//! shell forwards the resulting value to the node — it never persists anything on its own.
//!
//! # It is a privacy control, not just a disk knob
//!
//! The cache is the operator's read-history cover: a larger cache holds more content the node can
//! reshare, which both widens the crowd a given read hides in and increases the node's contribution
//! to the network. Lowering it silently reduces that cover, and below [`TIER0_MIN_CAP_BYTES`] the
//! node's tier-0 relevancy caching switches off entirely (dig_ecosystem#1934). The copy this module
//! produces says so plainly rather than presenting the cap as a pure storage setting.

/// One binary mebibyte.
pub const MIB: u64 = 1024 * 1024;
/// One binary gibibyte.
pub const GIB: u64 = 1024 * MIB;

/// The smallest cap the node honours: it floors any lower request at 64 MiB (the
/// `dig-node-control-interface` `control.cache.setCap` contract). The tray refuses a smaller value
/// up front rather than letting the node silently floor it, so the number the user sees applied is
/// the number they asked for.
pub const MIN_CACHE_CAP_BYTES: u64 = 64 * MIB;

/// The node's default cap when none is configured — 1 GiB (1024³ bytes), the `DEFAULT_CACHE_CAP` the
/// node ships. Named in the tray so a person can restore the default deliberately.
pub const DEFAULT_CACHE_CAP_BYTES: u64 = GIB;

/// The largest cap the tray will accept — a 1 TiB sanity ceiling. Not a node limit; it exists so a
/// fat-fingered `"999 GB"` cannot ask the node to reserve an absurd amount of disk. A user who
/// genuinely wants more can raise it later; the point is that a slip is caught, not that the number
/// is a hard maximum for the system.
pub const MAX_CACHE_CAP_BYTES: u64 = 1024 * GIB;

/// Below this cap the node disables its tier-0 relevancy caching (dig_ecosystem#1934), so a person
/// dropping under it loses the strongest layer of read-history cover. Used only to WARN — it is not
/// a floor; the honest choice is the user's to make, informed.
pub const TIER0_MIN_CAP_BYTES: u64 = 512 * MIB;

/// The cap sizes the tray offers as one-click presets, smallest first. Every entry is at least
/// [`MIN_CACHE_CAP_BYTES`] and at most [`MAX_CACHE_CAP_BYTES`], and one is exactly
/// [`DEFAULT_CACHE_CAP_BYTES`] so the default is always reachable without typing.
pub const CACHE_PRESETS: [u64; 6] = [256 * MIB, 512 * MIB, GIB, 2 * GIB, 5 * GIB, 10 * GIB];

/// The node cache's current shape, as the tray needs it: the cap and how much is used against it.
///
/// Filled from the node's `control.status` snapshot (which embeds the cache view), so the tray shows
/// the node's real numbers and needs no separate read. Absent when no node is connected — the tray
/// then shows the control cannot act yet rather than a stale or invented figure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheSnapshot {
    /// The configured cap, in bytes.
    pub cap_bytes: u64,
    /// Bytes currently used on disk.
    pub used_bytes: u64,
}

/// Why a typed cache-size value could not be used, each mapping to the exact sentence the input
/// window shows so the user can correct it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapInputError {
    /// Nothing was typed.
    Empty,
    /// A number with no unit — rejected rather than guessed, because `512` could mean bytes or
    /// gibibytes and applying the wrong one silently is worse than asking again.
    MissingUnit,
    /// The text is not a number followed by a known unit.
    Unparseable,
    /// The value is zero — a cache that can hold nothing is never what a person means.
    Zero,
    /// Below the node's 64 MiB floor.
    TooSmall,
    /// Above the tray's sanity ceiling.
    TooLarge,
}

impl CapInputError {
    /// The user-facing explanation for this rejection, naming the bound where there is one so the
    /// person knows what to type instead.
    pub fn message(self) -> String {
        match self {
            Self::Empty => "Type a size, for example 2 GiB or 512 MiB.".to_string(),
            Self::MissingUnit => {
                "Include a unit so the size is unambiguous — for example 2 GiB or 512 MiB."
                    .to_string()
            }
            Self::Unparseable => {
                "That is not a size. Type a number and a unit, for example 2 GiB or 512 MiB."
                    .to_string()
            }
            Self::Zero => "The cache size cannot be zero — nothing could be cached.".to_string(),
            Self::TooSmall => format!(
                "The smallest cache size is {}. Choose that or larger.",
                format_cap(MIN_CACHE_CAP_BYTES)
            ),
            Self::TooLarge => format!(
                "That is larger than the {} maximum. Choose a smaller size.",
                format_cap(MAX_CACHE_CAP_BYTES)
            ),
        }
    }
}

/// What applying a validated cap will do, so the shell knows whether to warn first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapChange {
    /// The new cap is at or above what is currently used, so nothing is evicted — apply it directly.
    Apply {
        /// The cap to send to the node.
        bytes: u64,
    },
    /// The new cap is BELOW current usage, so the node will evict cached content to fit. The user
    /// must understand and confirm this before it happens, not discover it after.
    ConfirmEviction {
        /// The cap the user asked for.
        bytes: u64,
        /// What is used now, so the warning can name how much would be evicted.
        used_bytes: u64,
    },
}

/// Format a byte count as a binary size a person reads — `"350 MiB"`, `"1 GiB"`, `"1.5 GiB"`.
///
/// Binary units throughout (1 GiB = 1024³), matching how the cap is stored, so the displayed number
/// and the stored bytes never disagree (dig_ecosystem#2002 requirement 7). Exact multiples render
/// without a fraction; anything else keeps one decimal place, which is as precise as a cache size
/// ever needs to read.
pub fn format_cap(bytes: u64) -> String {
    if bytes >= GIB {
        format_unit(bytes, GIB, "GiB")
    } else {
        format_unit(bytes, MIB, "MiB")
    }
}

/// Render `bytes` in `unit`, dropping a trailing `.0` so whole sizes read cleanly.
fn format_unit(bytes: u64, unit: u64, suffix: &str) -> String {
    let whole = bytes / unit;
    let tenths = (bytes % unit) * 10 / unit;
    if tenths == 0 {
        format!("{whole} {suffix}")
    } else {
        format!("{whole}.{tenths} {suffix}")
    }
}

/// Parse a typed cache size into a validated byte count, or the reason it was rejected.
///
/// Accepts a number and a required unit (`MiB`/`MB`/`M`, `GiB`/`GB`/`G`, case-insensitive). `MB`/`GB`
/// are treated as their binary siblings deliberately: a cache cap is a binary quantity, and silently
/// interpreting `2 GB` as 2·10⁹ while the node stores and reports 1024³-based figures is exactly the
/// GiB-vs-GB mismatch requirement 7 exists to prevent — the input body states this. A bare number is
/// rejected ([`CapInputError::MissingUnit`]) rather than guessed.
pub fn parse_cap_input(text: &str) -> Result<u64, CapInputError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(CapInputError::Empty);
    }
    let split = trimmed
        .find(|c: char| c.is_ascii_alphabetic())
        .ok_or(CapInputError::MissingUnit)?;
    let (number, unit) = trimmed.split_at(split);
    let value: f64 = number
        .trim()
        .parse()
        .map_err(|_| CapInputError::Unparseable)?;
    if !value.is_finite() || value < 0.0 {
        return Err(CapInputError::Unparseable);
    }
    let unit_bytes = match unit.trim().to_ascii_lowercase().as_str() {
        "m" | "mb" | "mib" => MIB,
        "g" | "gb" | "gib" => GIB,
        _ => return Err(CapInputError::Unparseable),
    };
    let bytes = (value * unit_bytes as f64) as u64;
    validate_cap(bytes)
}

/// Range-check an already-numeric cap, returning the byte count or the bound it violates.
///
/// Separate from [`parse_cap_input`] so a preset (which is a number, not typed text) shares the exact
/// same bounds without going through unit parsing.
pub fn validate_cap(bytes: u64) -> Result<u64, CapInputError> {
    if bytes == 0 {
        Err(CapInputError::Zero)
    } else if bytes < MIN_CACHE_CAP_BYTES {
        Err(CapInputError::TooSmall)
    } else if bytes > MAX_CACHE_CAP_BYTES {
        Err(CapInputError::TooLarge)
    } else {
        Ok(bytes)
    }
}

/// Decide whether applying `bytes` (already validated) needs an eviction confirmation first.
///
/// The one rule: a cap below what is currently used forces the node to evict, so it is the
/// [`CapChange::ConfirmEviction`] path; at or above usage nothing is lost and it applies directly.
pub fn plan_cap_change(bytes: u64, used_bytes: u64) -> CapChange {
    if bytes < used_bytes {
        CapChange::ConfirmEviction { bytes, used_bytes }
    } else {
        CapChange::Apply { bytes }
    }
}

/// The honest explanation of what the cache cap trades off, shown by the tray's "About the cache…"
/// notice.
///
/// It states the disk fact, the privacy fact, and the units — the three things a person needs to
/// make an informed choice — without overclaiming or hiding the downside of lowering it.
pub fn privacy_notice_body() -> String {
    format!(
        "The cache is the content your node keeps on disk and can reshare to others. A single \
         capsule is about 135 MB, so the {default} default holds roughly 7 of them.\n\n\
         It is also your privacy cover: the more your node caches and reshares, the larger the crowd \
         your own reads blend into, and the more you contribute to the network. Raising the limit \
         increases both; lowering it reduces them. Below {tier0} the node stops its most relevant \
         caching layer, so keep it at {tier0} or above for the strongest cover.\n\n\
         Sizes are binary: 1 GiB is 1024×1024×1024 bytes. Changes take effect immediately — no \
         restart.",
        default = format_cap(DEFAULT_CACHE_CAP_BYTES),
        tier0 = format_cap(TIER0_MIN_CAP_BYTES),
    )
}

/// The eviction-warning body shown BEFORE a below-usage cap is applied, naming how much cached
/// content the node will delete to fit.
pub fn eviction_warning_body(new_cap: u64, used_bytes: u64) -> String {
    let evicted = used_bytes.saturating_sub(new_cap);
    format!(
        "Your node is using {used} of cache. Lowering the limit to {cap} means it will delete about \
         {evicted} of already-cached content to fit, and reduce the privacy cover a larger cache \
         gives you. This cannot be undone, but the content can be fetched again later.",
        used = format_cap(used_bytes),
        cap = format_cap(new_cap),
        evicted = format_cap(evicted),
    )
}

/// The guidance shown in the custom-size input window: the accepted format and the unit convention.
pub fn custom_input_body() -> String {
    format!(
        "Type the maximum size for your node's content cache, with a unit — for example 2 GiB or \
         512 MiB. Sizes are binary (1 GiB = 1024 MiB). The smallest allowed is {min}; the default \
         is {default}.",
        min = format_cap(MIN_CACHE_CAP_BYTES),
        default = format_cap(DEFAULT_CACHE_CAP_BYTES),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_are_all_within_the_accepted_range() {
        for &preset in &CACHE_PRESETS {
            assert!(
                validate_cap(preset).is_ok(),
                "preset {preset} must be an acceptable cap"
            );
        }
    }

    #[test]
    fn the_default_is_one_binary_gibibyte_and_is_a_preset() {
        assert_eq!(DEFAULT_CACHE_CAP_BYTES, 1024 * 1024 * 1024);
        assert!(
            CACHE_PRESETS.contains(&DEFAULT_CACHE_CAP_BYTES),
            "the default must be reachable without typing"
        );
    }

    #[test]
    fn the_floor_matches_the_node_contract() {
        // The node floors setCap at 64 MiB; the tray's minimum must be exactly that so it neither
        // rejects a value the node would take nor accepts one the node would silently floor.
        assert_eq!(MIN_CACHE_CAP_BYTES, 64 * 1024 * 1024);
    }

    // ---- Formatting: the displayed number must match the stored bytes (requirement 7). ----

    #[test]
    fn format_uses_binary_units_and_drops_trailing_zeroes() {
        assert_eq!(format_cap(GIB), "1 GiB");
        assert_eq!(format_cap(350 * MIB), "350 MiB");
        assert_eq!(format_cap(512 * MIB), "512 MiB");
        assert_eq!(format_cap(2 * GIB), "2 GiB");
        // A non-exact multiple keeps one decimal rather than rounding to a wrong whole number.
        assert_eq!(format_cap(GIB + 512 * MIB), "1.5 GiB");
    }

    #[test]
    fn format_of_the_default_reads_as_one_gib_not_1000_mb() {
        // The GiB-vs-GB trap: 1 GiB is 1024 MiB, and the label must say GiB, never "1000 MB".
        let text = format_cap(DEFAULT_CACHE_CAP_BYTES);
        assert_eq!(text, "1 GiB");
        assert!(!text.contains("GB"), "must not present a decimal-GB figure");
    }

    // ---- Parsing: bounds pinned from BOTH sides. ----

    #[test]
    fn parses_a_number_with_a_binary_or_decimal_unit_as_binary() {
        assert_eq!(parse_cap_input("2 GiB"), Ok(2 * GIB));
        assert_eq!(parse_cap_input("512 MiB"), Ok(512 * MIB));
        // GB/MB are accepted but interpreted as binary, so 2 GB stores the SAME bytes as 2 GiB —
        // the node reports binary figures, so a decimal interpretation would mismatch (req 7).
        assert_eq!(parse_cap_input("2 GB"), parse_cap_input("2 GiB"));
        assert_eq!(parse_cap_input("512mb"), Ok(512 * MIB));
        assert_eq!(parse_cap_input("1.5 GiB"), Ok(GIB + 512 * MIB));
    }

    #[test]
    fn a_bare_number_is_rejected_rather_than_guessed() {
        assert_eq!(parse_cap_input("512"), Err(CapInputError::MissingUnit));
    }

    #[test]
    fn empty_and_garbage_are_named_distinctly() {
        assert_eq!(parse_cap_input("   "), Err(CapInputError::Empty));
        // Alphabetic with no leading number: the number part is empty, so it is unparseable rather
        // than merely missing a unit (that case is a bare number — pinned above).
        assert_eq!(parse_cap_input("big"), Err(CapInputError::Unparseable));
        assert_eq!(
            parse_cap_input("1.2.3 GiB"),
            Err(CapInputError::Unparseable)
        );
        assert_eq!(parse_cap_input("2 TB"), Err(CapInputError::Unparseable));
    }

    #[test]
    fn zero_is_rejected_specifically() {
        assert_eq!(parse_cap_input("0 GiB"), Err(CapInputError::Zero));
        assert_eq!(validate_cap(0), Err(CapInputError::Zero));
    }

    #[test]
    fn the_lower_bound_is_pinned_from_both_sides() {
        // One below the floor must fail; the floor itself must pass.
        assert_eq!(
            validate_cap(MIN_CACHE_CAP_BYTES - 1),
            Err(CapInputError::TooSmall)
        );
        assert_eq!(validate_cap(MIN_CACHE_CAP_BYTES), Ok(MIN_CACHE_CAP_BYTES));
    }

    #[test]
    fn the_upper_bound_is_pinned_from_both_sides() {
        assert_eq!(validate_cap(MAX_CACHE_CAP_BYTES), Ok(MAX_CACHE_CAP_BYTES));
        assert_eq!(
            validate_cap(MAX_CACHE_CAP_BYTES + 1),
            Err(CapInputError::TooLarge)
        );
    }

    // ---- The eviction decision (requirement 4). ----

    #[test]
    fn a_cap_at_or_above_usage_applies_without_eviction() {
        // Above usage: no eviction.
        assert_eq!(
            plan_cap_change(2 * GIB, GIB),
            CapChange::Apply { bytes: 2 * GIB }
        );
        // Exactly at usage: still nothing to evict — the boundary must be Apply, not a spurious
        // warning. Pinned because `<=` vs `<` is exactly where this kind of guard goes wrong.
        assert_eq!(plan_cap_change(GIB, GIB), CapChange::Apply { bytes: GIB });
    }

    #[test]
    fn a_cap_below_usage_requires_an_eviction_confirmation() {
        // One byte below usage is enough to force eviction — the warning is not reserved for a large
        // drop, because any deletion of the user's cached content is theirs to approve first.
        assert_eq!(
            plan_cap_change(GIB - 1, GIB),
            CapChange::ConfirmEviction {
                bytes: GIB - 1,
                used_bytes: GIB
            }
        );
    }

    #[test]
    fn the_eviction_warning_names_how_much_is_deleted() {
        let body = eviction_warning_body(512 * MIB, GIB);
        // 1 GiB used, capped at 512 MiB → ~512 MiB evicted, and the warning must say so and warn it
        // cannot be undone.
        assert!(
            body.contains("512 MiB"),
            "must name the evicted amount: {body}"
        );
        assert!(body.contains("1 GiB"), "must name current usage: {body}");
        assert!(
            body.contains("cannot be undone"),
            "must warn of the loss: {body}"
        );
    }

    // ---- The honest privacy copy (requirement 6). ----

    #[test]
    fn the_privacy_notice_states_disk_privacy_and_units_without_hiding_the_downside() {
        let body = privacy_notice_body();
        assert!(body.contains("135 MB"), "names the capsule size: {body}");
        assert!(
            body.contains("privacy"),
            "names the privacy trade-off: {body}"
        );
        assert!(
            body.contains("lowering it reduces"),
            "is honest that lowering costs privacy: {body}"
        );
        assert!(
            body.contains("1024"),
            "is explicit that sizes are binary (req 7): {body}"
        );
        assert!(
            body.to_lowercase().contains("immediately")
                || body.contains("no \nrestart")
                || body.contains("no restart"),
            "must not tell the user to restart (req 3): {body}"
        );
    }

    #[test]
    fn the_custom_input_body_names_the_format_the_floor_and_the_default() {
        let body = custom_input_body();
        assert!(body.contains("GiB"), "shows the unit form: {body}");
        assert!(
            body.contains(&format_cap(MIN_CACHE_CAP_BYTES)),
            "names the floor: {body}"
        );
        assert!(
            body.contains(&format_cap(DEFAULT_CACHE_CAP_BYTES)),
            "names the default: {body}"
        );
    }
}
