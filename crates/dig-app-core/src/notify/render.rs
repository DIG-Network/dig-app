//! Notification rendering: honest amount/asset formatting + the per-OS native toast backends.
//!
//! The formatting half ([`direction_line`], [`format_amount`], [`asset_label`]) is pure and
//! unit-tested. The per-OS half drives the platform's native toast as a SUBPROCESS (no new
//! dependency, no untested FFI in the custody-adjacent app): Linux `notify-send`, macOS `osascript
//! display notification`. Windows has no dependency-free toast subprocess, so it falls back to the
//! [`LoggingNotifier`] for now (native WinRT toast is the #970 follow-up) — every backend is
//! best-effort and a failure is swallowed, so a missed toast never breaks the app.

use std::collections::BTreeMap;

use dig_events_protocol::AssetId;

use super::{AssetTotal, NativeNotifier, Notification};

/// Format one direction's coalesced totals as a line, or `None` when nothing moved that way.
///
/// One payment reads naturally (`"Received 1 XCH"`); a burst is counted and totalled (`"Received 3
/// payments: 2 XCH total"`); a multi-asset burst lists each asset (`"Received 4 payments: 2 XCH,
/// 1.5 $DIG"`).
pub(super) fn direction_line(
    verb: &str,
    totals: &BTreeMap<Option<AssetId>, AssetTotal>,
    dig_asset_id: Option<&AssetId>,
) -> Option<String> {
    if totals.is_empty() {
        return None;
    }
    let count: u64 = totals.values().map(|t| t.count).sum();
    let amounts = totals
        .iter()
        .map(|(asset, total)| {
            format!(
                "{} {}",
                format_amount(asset.as_ref(), total.mojos),
                asset_label(asset.as_ref(), dig_asset_id)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    Some(match (count, totals.len()) {
        (1, _) => format!("{verb} {amounts}"),
        (_, 1) => format!("{verb} {count} payments: {amounts} total"),
        (_, _) => format!("{verb} {count} payments: {amounts}"),
    })
}

/// The human label for an asset: `XCH` for the native asset, `$DIG` for the DIG CAT, otherwise a
/// short form of the CAT asset id. Never a false ticker (§6.0 honest).
pub(super) fn asset_label(asset: Option<&AssetId>, dig_asset_id: Option<&AssetId>) -> String {
    match asset {
        None => "XCH".to_string(),
        Some(id) if Some(id) == dig_asset_id => "$DIG".to_string(),
        Some(id) => short_asset(&id.to_string()),
    }
}

/// Abbreviate a long asset id for display (`abcdef…7890`), leaving short ids intact.
fn short_asset(id: &str) -> String {
    if id.len() > 12 {
        format!("{}…{}", &id[..6], &id[id.len() - 4..])
    } else {
        id.to_string()
    }
}

/// Format a base-unit amount for an asset: XCH has 12 decimals (mojos), CATs 3 (the Chia CAT
/// convention), with trailing zeros trimmed for a glanceable value.
pub(super) fn format_amount(asset: Option<&AssetId>, mojos: u128) -> String {
    let decimals = if asset.is_none() { 12 } else { 3 };
    let divisor = 10u128.pow(decimals);
    let whole = mojos / divisor;
    let frac = mojos % divisor;
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:0width$}", width = decimals as usize);
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

/// A fail-safe notifier that logs instead of drawing a toast — the headless / unsupported-target
/// fallback, and the base for the #970 native-backend follow-ups. Never panics.
#[derive(Debug, Default, Clone, Copy)]
pub struct LoggingNotifier;

impl NativeNotifier for LoggingNotifier {
    fn show(&self, notification: &Notification) {
        tracing::info!(
            title = %notification.title,
            body = %notification.body,
            "wallet notification (no native toast backend on this host)"
        );
    }
}

/// Select the native notifier for this host: the per-OS subprocess backend, or the fail-safe
/// [`LoggingNotifier`] when none is available.
pub fn native_notifier() -> Box<dyn NativeNotifier> {
    #[cfg(target_os = "linux")]
    {
        Box::new(platform::NotifySend)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(platform::OsaScript)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Box::new(LoggingNotifier)
    }
}

/// The per-OS subprocess backends. Each shells out to the platform's notification tool WITHOUT a
/// shell (args are passed directly), so notification text cannot inject a command; macOS additionally
/// neutralizes the AppleScript string literal (per the native-dialog-markup-neutralize rule).
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use super::{NativeNotifier, Notification};

    /// Linux: `notify-send <title> <body>` (libnotify). Args are separate, so no shell injection.
    #[cfg(target_os = "linux")]
    pub struct NotifySend;

    #[cfg(target_os = "linux")]
    impl NativeNotifier for NotifySend {
        fn show(&self, notification: &Notification) {
            let _ = std::process::Command::new("notify-send")
                .arg(&notification.title)
                .arg(&notification.body)
                .spawn();
        }
    }

    /// macOS: `osascript -e 'display notification "body" with title "title"'`. The two fields are
    /// interpolated into an AppleScript string literal, so each is neutralized (backslashes +
    /// double-quotes escaped) before interpolation.
    #[cfg(target_os = "macos")]
    pub struct OsaScript;

    #[cfg(target_os = "macos")]
    impl NativeNotifier for OsaScript {
        fn show(&self, notification: &Notification) {
            let script = format!(
                "display notification \"{}\" with title \"{}\"",
                applescript_escape(&notification.body),
                applescript_escape(&notification.title),
            );
            let _ = std::process::Command::new("osascript")
                .arg("-e")
                .arg(script)
                .spawn();
        }
    }

    /// Escape a string for safe interpolation into an AppleScript double-quoted literal.
    #[cfg(target_os = "macos")]
    fn applescript_escape(text: &str) -> String {
        text.replace('\\', "\\\\").replace('"', "\\\"")
    }

    #[cfg(all(test, target_os = "macos"))]
    mod tests {
        use super::applescript_escape;

        #[test]
        fn escaping_neutralizes_quotes_and_backslashes() {
            assert_eq!(applescript_escape(r#"a"b\c"#), r#"a\"b\\c"#);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn total(count: u64, mojos: u128) -> AssetTotal {
        AssetTotal { count, mojos }
    }

    #[test]
    fn xch_amount_trims_trailing_zeros() {
        assert_eq!(format_amount(None, 2_000_000_000_000), "2");
        assert_eq!(format_amount(None, 1_500_000_000_000), "1.5");
        assert_eq!(format_amount(None, 1), "0.000000000001");
    }

    #[test]
    fn cat_amount_uses_three_decimals() {
        assert_eq!(format_amount(Some(&AssetId("t".into())), 3_000), "3");
        assert_eq!(format_amount(Some(&AssetId("t".into())), 1_500), "1.5");
    }

    #[test]
    fn asset_label_names_native_dig_and_other_cats() {
        let dig = AssetId("dig".into());
        assert_eq!(asset_label(None, Some(&dig)), "XCH");
        assert_eq!(asset_label(Some(&dig), Some(&dig)), "$DIG");
        let other = AssetId("0123456789abcdef0123".into());
        assert_eq!(asset_label(Some(&other), Some(&dig)), "012345…0123");
    }

    #[test]
    fn direction_line_singular_plural_and_multi_asset() {
        let mut single = BTreeMap::new();
        single.insert(None, total(1, 1_000_000_000_000));
        assert_eq!(
            direction_line("Received", &single, None).unwrap(),
            "Received 1 XCH"
        );

        let mut burst = BTreeMap::new();
        burst.insert(None, total(3, 2_000_000_000_000));
        assert_eq!(
            direction_line("Received", &burst, None).unwrap(),
            "Received 3 payments: 2 XCH total"
        );

        let dig = AssetId("dig".into());
        let mut multi = BTreeMap::new();
        multi.insert(None, total(1, 1_000_000_000_000));
        multi.insert(Some(dig.clone()), total(1, 1_500));
        let line = direction_line("Received", &multi, Some(&dig)).unwrap();
        assert!(line.contains("2 payments"), "{line}");
        assert!(line.contains("1 XCH"), "{line}");
        assert!(line.contains("1.5 $DIG"), "{line}");
    }

    #[test]
    fn empty_direction_is_none() {
        assert!(direction_line("Received", &BTreeMap::new(), None).is_none());
    }

    #[test]
    fn logging_notifier_never_panics() {
        LoggingNotifier.show(&Notification {
            title: "t".into(),
            body: "b".into(),
        });
    }

    #[test]
    fn native_notifier_factory_returns_a_usable_notifier() {
        native_notifier().show(&Notification {
            title: "DIG".into(),
            body: "Received 1 XCH".into(),
        });
    }
}
