//! The i18n guards (dig_ecosystem#2328 Decision 4). Per-locale guards assert only MECHANICAL
//! properties; a completeness gap, a dropped placeable, a torn run, a lost brand literal, an
//! injected digit, or a catalog that is English wearing a different file name.
//!
//! **Status at this commit:** only the `i18n` module itself is converted to `Msg`; phase 1 ships as
//! FOUNDATION ONLY (engine + 14 catalogs + `AgentConfig.language`; no module has moved its consts
//! to `Msg` yet, so K = 0). Test 1's former `K.len() > 100` completeness floor (Decision 5: ~150
//! keys across 12 files) moved to the phase-1b child, dig_ecosystem#3225, since
//! it would be permanently red until those files convert; the load-bearing catalog-parity checks
//! stay here.

use super::catalog;
use super::{Language, SUPPORTED};
use std::collections::BTreeSet;

/// Every `Msg::new("…")` string literal anywhere under this crate's `src/`, found by a plain text
/// scan (no proc-macro, no AST — the same idiom `copy_hygiene.rs` uses for its own sweeps). Stops
/// at nothing; `#[cfg(test)]` blocks are included deliberately because a test fixture that invents
/// its own key would otherwise be invisible to the completeness guard it is supposed to be
/// checked by.
fn every_msg_key_in_source() -> BTreeSet<String> {
    let src_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut keys = BTreeSet::new();
    walk(std::path::Path::new(src_dir), &mut keys);
    keys
}

fn walk(dir: &std::path::Path, keys: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, keys);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            // This guard's own file: it carries the literal text `Msg::new(` as data (its NEEDLE
            // constant, its doc comments), which is not a call site and would corrupt K.
            if path.file_name().and_then(|f| f.to_str()) == Some("tests.rs")
                && path
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|f| f.to_str())
                    == Some("i18n")
            {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&path) {
                extract_msg_keys(&text, keys);
            }
        }
    }
}

fn extract_msg_keys(text: &str, keys: &mut BTreeSet<String>) {
    const NEEDLE: &str = "Msg::new(";
    let mut rest = text;
    while let Some(pos) = rest.find(NEEDLE) {
        rest = &rest[pos + NEEDLE.len()..];
        let rest_trimmed = rest.trim_start();
        if let Some(after_quote) = rest_trimmed.strip_prefix('"') {
            if let Some(end) = after_quote.find('"') {
                keys.insert(after_quote[..end].to_string());
            }
        }
    }
}

/// The catalog's message ids that are not required to appear in `K` — declared once per catalog,
/// by the facade itself, never by a call site.
fn meta_keys() -> BTreeSet<String> {
    ["language-name", "catalog-review-state"]
        .into_iter()
        .map(String::from)
        .collect()
}

fn catalog_ids(lang: Language) -> BTreeSet<String> {
    catalog::parse_messages(lang)
        .into_iter()
        .map(|m| m.id)
        .collect()
}

#[test]
fn every_locale_carries_every_key_and_no_more() {
    let k = every_msg_key_in_source();
    let meta = meta_keys();
    let fixture: BTreeSet<String> = FIXTURE_KEYS.iter().map(|s| s.to_string()).collect();
    let mut expected: BTreeSet<String> = k.union(&meta).cloned().collect();
    expected.extend(fixture);

    for lang in SUPPORTED {
        let ids = catalog_ids(lang);
        assert!(!ids.is_empty(), "{}: catalog is empty", lang.tag());
        let missing: Vec<_> = expected.difference(&ids).collect();
        let orphan: Vec<_> = ids.difference(&expected).collect();
        assert!(
            missing.is_empty() && orphan.is_empty(),
            "{}: missing {:?}, orphan {:?}",
            lang.tag(),
            missing,
            orphan
        );
    }
    // (a) every catalog's id set equals `expected` above (checked in the loop), so all `SUPPORTED`
    // locales are pairwise identical to each other by transitivity, and each is asserted non-empty.
    // (b) every `Msg::new("…")` literal found in `src/**/*.rs` (`k`, via `expected`) is required
    // present in every catalog — the same `missing` diff in the loop. The K.len() > 100 floor that
    // used to close this test moved to the phase-1b child, dig_ecosystem#3225:
    // phase 1 here is foundation only (engine + 14 catalogs + `AgentConfig.language`), no module
    // has moved its consts to `Msg` yet, so K = 0 and a >100 floor would be permanently red.
}

#[test]
fn every_placeable_agrees_with_english() {
    let en: std::collections::HashMap<String, BTreeSet<String>> =
        catalog::parse_messages(Language::En)
            .into_iter()
            .map(|m| (m.id, m.variables))
            .collect();

    for lang in SUPPORTED {
        if lang == Language::En {
            continue;
        }
        for message in catalog::parse_messages(lang) {
            if let Some(expected) = en.get(&message.id) {
                assert_eq!(
                    &message.variables,
                    expected,
                    "{}:{} placeables {:?} != en's {:?}",
                    lang.tag(),
                    message.id,
                    message.variables,
                    expected
                );
            }
        }
    }
}

#[test]
fn no_catalog_value_carries_a_torn_run() {
    for lang in SUPPORTED {
        for message in catalog::parse_messages(lang) {
            assert!(
                !message.value.contains("   "),
                "{}:{} value carries a torn run: {:?}",
                lang.tag(),
                message.id,
                message.value
            );
        }
    }
}

/// Catalog keys exercised ONLY by test fixtures, not product code. The source scan (which
/// skips tests.rs by design) cannot see these literals; they leave the catalogs when phase 1b
/// (dig_ecosystem#3225) converts the first product module to `Msg`.
const FIXTURE_KEYS: &[&str] = &["balance-known"];

/// Brand literals that must survive translation verbatim.
const BRAND_LITERALS: &[&str] = &["$DIG", "XCH", "DIGHub", "chia://", "dig://"];

#[test]
fn brand_literals_survive_translation() {
    let en: std::collections::HashMap<String, String> = catalog::parse_messages(Language::En)
        .into_iter()
        .map(|m| (m.id, m.value))
        .collect();

    for lang in SUPPORTED {
        if lang == Language::En {
            continue;
        }
        for message in catalog::parse_messages(lang) {
            let Some(en_value) = en.get(&message.id) else {
                continue;
            };
            for brand in BRAND_LITERALS {
                if en_value.contains(brand) {
                    assert!(
                        message.value.contains(brand),
                        "{}:{} dropped brand literal {brand:?}",
                        lang.tag(),
                        message.id
                    );
                }
            }
        }
    }
}

#[test]
fn digit_free_where_english_is_digit_free() {
    let en: std::collections::HashMap<String, String> = catalog::parse_messages(Language::En)
        .into_iter()
        .map(|m| (m.id, m.value))
        .collect();

    for lang in SUPPORTED {
        if lang == Language::En {
            continue;
        }
        for message in catalog::parse_messages(lang) {
            let Some(en_value) = en.get(&message.id) else {
                continue;
            };
            if !en_value.chars().any(|c| c.is_ascii_digit()) {
                assert!(
                    !message.value.chars().any(|c| c.is_ascii_digit()),
                    "{}:{} injected a digit english never had",
                    lang.tag(),
                    message.id
                );
            }
        }
    }
}

#[test]
fn a_locale_is_not_english_in_disguise() {
    let en: std::collections::HashMap<String, String> = catalog::parse_messages(Language::En)
        .into_iter()
        .map(|m| (m.id, m.value))
        .collect();

    for lang in SUPPORTED {
        if lang == Language::En {
            continue;
        }
        let mut comparable = 0usize;
        let mut differing = 0usize;
        for message in catalog::parse_messages(lang) {
            let Some(en_value) = en.get(&message.id) else {
                continue;
            };
            let is_only_punctuation_or_brand = en_value
                .chars()
                .all(|c| !c.is_alphanumeric() || BRAND_LITERALS.iter().any(|b| b.contains(c)));
            if is_only_punctuation_or_brand {
                continue;
            }
            comparable += 1;
            if message.value != *en_value {
                differing += 1;
            }
        }
        if comparable == 0 {
            continue;
        }
        let ratio = differing as f64 / comparable as f64;
        assert!(
            ratio >= 0.8,
            "{}: only {differing}/{comparable} values differ from en (needs >= 80%)",
            lang.tag()
        );
    }
}

#[test]
fn every_embedded_catalog_is_on_disk_and_vice_versa() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/i18n");
    let on_disk: BTreeSet<String> = std::fs::read_dir(dir)
        .expect("i18n/ catalog directory exists")
        .flatten()
        .filter_map(|e| {
            e.path()
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .collect();
    let embedded: BTreeSet<String> = SUPPORTED.iter().map(|l| l.tag().to_string()).collect();
    assert_eq!(on_disk, embedded, "on-disk catalogs and SUPPORTED disagree");
}

#[test]
fn negotiation_falls_back_deterministically() {
    let cases: &[(&str, Language)] = &[
        ("zh", Language::ZhCn),
        ("zh-HK", Language::ZhTw),
        ("pt", Language::PtBr),
        ("pt-PT", Language::PtBr),
        ("es-MX", Language::Es),
        ("en-GB", Language::En),
        ("xx-XX", Language::En),
    ];
    for (tag, expected) in cases {
        assert_eq!(super::resolve(tag), *expected, "resolve({tag:?})");
    }
}

#[test]
fn a_missing_key_never_renders_empty() {
    let msg = super::Msg::new("this-key-exists-nowhere");
    let rendered = msg.text();
    assert!(!rendered.is_empty());
    assert_eq!(rendered, "this-key-exists-nowhere");
}

/// `activate`/`current_language` are process-wide (by design — a language switch must repaint
/// every label without threading a parameter through every call site). Serialized with the other
/// test in this file that also calls `activate`, so `cargo test`'s default thread-parallel runner
/// cannot interleave two switches — [`Msg::with_in`] is what every OTHER test in this module uses
/// instead, precisely to avoid needing this lock.
static ACTIVATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn activate_changes_current_language_and_rendering() {
    let _guard = ACTIVATE_LOCK.lock().unwrap();
    let args = super::Args::new()
        .text("dig", "1".to_string())
        .text("xch", "0".to_string());
    let msg = super::Msg::new("balance-known");

    super::activate(Language::De);
    assert_eq!(super::current_language(), Language::De);
    assert!(msg.with(&args).starts_with("Guthaben"));

    super::activate(Language::En);
    assert_eq!(super::current_language(), Language::En);
    assert!(msg.with(&args).starts_with("Balance"));
}

#[test]
fn args_text_fills_a_placeable_without_touching_money_formatting() {
    let args = super::Args::new()
        .text("dig", "12.5".to_string())
        .text("xch", "0.001".to_string());
    let msg = super::Msg::new("balance-known");
    assert_eq!(
        msg.with_in(Language::En, &args),
        "Balance: 12.5 $DIG · 0.001 XCH"
    );
}
