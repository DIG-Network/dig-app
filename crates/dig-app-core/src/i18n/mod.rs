//! The language of the copy (dig_ecosystem#2328, SPEC §3.1c-x).
//!
//! Every sentence dig-app shows a person is a [`Msg`] — a typed newtype over a catalog key that
//! renders in whichever [`Language`] is in force. The fourteen catalogs (`crates/dig-app-core/i18n/
//! <tag>.ftl`, one per [`SUPPORTED`] language) are `fluent` resources embedded at compile time
//! ([`catalog`]); the language in force is detected from the OS, negotiated against what dig-app
//! ships ([`negotiate`]), chosen in Settings, persisted in `AgentConfig.language`, and applied
//! without restart by calling [`activate`].
//!
//! Money never routes through a catalog's number formatting: an amount is rendered by
//! [`crate::amount::format_asset_amount`] first, and enters a message only as
//! [`Args::text`]. [`Args::count`] exists for plural selectors only.

mod catalog;
mod negotiate;

#[cfg(test)]
mod tests;

use std::sync::atomic::{AtomicUsize, Ordering};

/// A language dig-app has a catalog for. The order here is also `SUPPORTED`'s order (the order the
/// chooser draws them in, English first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum Language {
    En,
    ZhCn,
    ZhTw,
    Ko,
    Ja,
    Ru,
    Es,
    PtBr,
    Fr,
    De,
    Tr,
    Vi,
    Id,
    Hi,
}

impl Language {
    /// The BCP-47 tag this language's catalog file is named for (`i18n/<tag>.ftl`) and the tag
    /// `SUPPORTED`/negotiation/persistence all speak.
    pub const fn tag(self) -> &'static str {
        match self {
            Language::En => "en",
            Language::ZhCn => "zh-CN",
            Language::ZhTw => "zh-TW",
            Language::Ko => "ko",
            Language::Ja => "ja",
            Language::Ru => "ru",
            Language::Es => "es",
            Language::PtBr => "pt-BR",
            Language::Fr => "fr",
            Language::De => "de",
            Language::Tr => "tr",
            Language::Vi => "vi",
            Language::Id => "id",
            Language::Hi => "hi",
        }
    }

    /// The language whose tag is exactly `tag`, if dig-app ships a catalog for it. Case-sensitive —
    /// `SUPPORTED` tags are the canonical spelling `AgentConfig.language` is stored and compared as.
    pub fn from_tag(tag: &str) -> Option<Language> {
        use strum::IntoEnumIterator;
        Language::iter().find(|l| l.tag() == tag)
    }
}

/// Every language dig-app carries a catalog for, English first. Fourteen entries — the ecosystem's
/// declared locale set (`frontend-baseline`).
pub const SUPPORTED: [Language; 14] = [
    Language::En,
    Language::ZhCn,
    Language::ZhTw,
    Language::Ko,
    Language::Ja,
    Language::Ru,
    Language::Es,
    Language::PtBr,
    Language::Fr,
    Language::De,
    Language::Tr,
    Language::Vi,
    Language::Id,
    Language::Hi,
];

/// The languages the chooser may actually offer today: those whose text the installed fonts can
/// paint (`window.rs`'s `install_fonts` ships Space Grotesk + egui's default stack — no CJK, no
/// Devanagari). Test 7 ([`tests`]) measures this against real glyph coverage rather than trusting
/// this list by construction; the fonts child (dig_ecosystem#3217 RF) grows it. Until then
/// zh-CN/zh-TW/ja/ko/hi stay un-offered — a language offered without glyphs would paint tofu.
pub const OFFERED: [Language; 9] = [
    Language::En,
    Language::Es,
    Language::PtBr,
    Language::Fr,
    Language::De,
    Language::Tr,
    Language::Vi,
    Language::Id,
    Language::Ru,
];

/// The language every [`Msg::text`] call renders in until [`activate`] changes it. Starts at
/// English so any code that runs before the shell reads `AgentConfig.language` at boot still
/// renders something rather than panicking.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// The language [`Msg::text`] renders in right now.
pub fn current_language() -> Language {
    SUPPORTED[ACTIVE.load(Ordering::Relaxed).min(SUPPORTED.len() - 1)]
}

/// Makes `lang` the language every subsequent [`Msg::text`] call renders in — the shell calls this
/// from `apply_a_chosen_language`, at boot and on every explicit choice, so the window and tray
/// repaint in the new language without a restart (SPEC §3.1c-x).
pub fn activate(lang: Language) {
    let index = SUPPORTED.iter().position(|l| *l == lang).unwrap_or(0);
    ACTIVE.store(index, Ordering::Relaxed);
}

/// Detects the OS locale (`sys-locale`) and negotiates it against [`SUPPORTED`], falling back to
/// English. This is what a fresh `agent.json` (no `language` field yet) resolves to at boot.
pub fn detect() -> Language {
    sys_locale::get_locale()
        .map(|tag| resolve(&tag))
        .unwrap_or(Language::En)
}

/// Negotiates a requested BCP-47 tag against [`SUPPORTED`], falling back to English. Used both for
/// OS detection and for validating a persisted `AgentConfig.language` tag.
pub fn resolve(requested: &str) -> Language {
    negotiate::resolve(requested)
}

/// A typed reference to one catalog message. `Copy`, so it slots into a `const` exactly where a
/// `&'static str` used to. Renders lazily — `text()` looks up the message in the language in force
/// at call time, never at construction, which is what makes a language switch repaint every label
/// without touching a single call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Msg(&'static str);

impl Msg {
    /// Builds a reference to the catalog message named `key`. `key` must exist in every catalog
    /// (test 1 in [`tests`] enforces this); a call site owns getting the key right, the same way it
    /// used to own getting the English sentence right.
    pub const fn new(key: &'static str) -> Msg {
        Msg(key)
    }

    /// The catalog key this message renders. Meant for the guards, not for UI.
    pub fn key(&self) -> &'static str {
        self.0
    }

    /// Renders in the language currently in force, with no placeables. A key missing from every
    /// catalog (should never happen once test 1 is green) renders as its own id, never `""`.
    pub fn text(&self) -> String {
        catalog::format(current_language(), self.0, None)
    }

    /// Renders in a specific language, no placeables — used by the language chooser to draw each
    /// row in that row's own language.
    pub fn text_in(&self, lang: Language) -> String {
        catalog::format(lang, self.0, None)
    }

    /// Renders in the language currently in force, filling placeables from `args`.
    pub fn with(&self, args: &Args) -> String {
        self.with_in(current_language(), args)
    }

    /// Renders in a specific language, filling placeables from `args` — used by the language
    /// chooser and by anything that must not depend on the process-wide language in force.
    pub fn with_in(&self, lang: Language, args: &Args) -> String {
        catalog::format_with_args(lang, self.0, &args.0)
    }
}

impl std::fmt::Display for Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

#[cfg(feature = "gui")]
impl From<Msg> for egui::WidgetText {
    fn from(msg: Msg) -> Self {
        msg.text().into()
    }
}

/// The placeables a catalog message may need filled. Exactly two ways to fill one: [`Args::text`]
/// for a value already rendered to a string (an amount ALREADY through
/// [`crate::amount::format_asset_amount`], a name, an address — never a raw number a catalog's
/// `NUMBER()` could reformat), and [`Args::count`] for a plural selector.
#[derive(Debug, Default)]
pub struct Args(fluent_bundle::FluentArgs<'static>);

impl Args {
    /// A fresh, empty placeable set.
    pub fn new() -> Args {
        Args(fluent_bundle::FluentArgs::new())
    }

    /// Fills `name` with a value that is already text — money enters a message ONLY this way,
    /// already formatted by [`crate::amount::format_asset_amount`]. Chainable.
    pub fn text(mut self, name: &'static str, value: impl Into<String>) -> Args {
        self.0
            .set(name, fluent_bundle::FluentValue::from(value.into()));
        self
    }

    /// Fills `name` with a count a plural selector branches on. Never money. Chainable.
    pub fn count(mut self, name: &'static str, value: u64) -> Args {
        self.0.set(name, fluent_bundle::FluentValue::from(value));
        self
    }
}
