//! Negotiating a requested BCP-47 tag against [`super::SUPPORTED`].
//!
//! A deterministic table (dig_ecosystem#2328 Decision 3) is checked first, because it encodes
//! ecosystem-specific choices `fluent-langneg`'s likely-subtails algorithm would not make on its
//! own (`zh` bare defaults to Simplified, not Traditional; `pt`/`pt-PT` fold to `pt-BR`, the only
//! Portuguese catalog dig-app ships). Anything the table does not name falls through to
//! `fluent-langneg`'s CLDR likely-subtags negotiation, then to English.

use fluent_langneg::{negotiate_languages, NegotiationStrategy};
use unic_langid::LanguageIdentifier;

use super::{Language, SUPPORTED};

pub(crate) fn resolve(requested: &str) -> Language {
    if let Some(lang) = deterministic_fallback(requested) {
        return lang;
    }

    let Ok(requested_id) = requested.parse::<LanguageIdentifier>() else {
        return Language::En;
    };
    let available: Vec<LanguageIdentifier> = SUPPORTED
        .iter()
        .filter_map(|l| l.tag().parse().ok())
        .collect();
    let default: LanguageIdentifier = Language::En
        .tag()
        .parse()
        .expect("'en' is a valid language tag");

    let negotiated = negotiate_languages(
        &[requested_id],
        &available,
        Some(&default),
        NegotiationStrategy::Filtering,
    );

    negotiated
        .first()
        .and_then(|id| Language::from_tag(&id.to_string()))
        .unwrap_or(Language::En)
}

/// The table Decision 3 names by hand: cases where the "closest" CLDR match is not the dig-app
/// catalog the ecosystem wants.
fn deterministic_fallback(tag: &str) -> Option<Language> {
    match tag {
        "zh" => Some(Language::ZhCn),
        "zh-HK" => Some(Language::ZhTw),
        "pt" | "pt-PT" => Some(Language::PtBr),
        "es-MX" => Some(Language::Es),
        "en-GB" => Some(Language::En),
        _ => None,
    }
}
