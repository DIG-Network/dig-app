//! The 14 embedded `.ftl` catalogs and lookup into them.
//!
//! Every catalog is `include_str!`-ed at compile time (no `rust-embed`, no build script — the
//! shape lock's reasoning: dig_ecosystem#2328 Decision 2) and parsed once into a `concurrent`
//! (`Sync`) `FluentBundle`, held for the process lifetime in a [`std::sync::OnceLock`].

use fluent_bundle::concurrent::FluentBundle;
use fluent_bundle::{FluentArgs, FluentResource};
use std::sync::OnceLock;

use super::Language;

/// The raw FTL source for `lang`'s catalog. The ONE place a fifteenth locale would need a new arm
/// — test 8 (every embedded catalog is on disk and vice versa) fails loudly if this list and
/// `crates/dig-app-core/i18n/*.ftl` on disk ever disagree.
pub(crate) fn source(lang: Language) -> &'static str {
    match lang {
        Language::En => include_str!("../../i18n/en.ftl"),
        Language::ZhCn => include_str!("../../i18n/zh-CN.ftl"),
        Language::ZhTw => include_str!("../../i18n/zh-TW.ftl"),
        Language::Ko => include_str!("../../i18n/ko.ftl"),
        Language::Ja => include_str!("../../i18n/ja.ftl"),
        Language::Ru => include_str!("../../i18n/ru.ftl"),
        Language::Es => include_str!("../../i18n/es.ftl"),
        Language::PtBr => include_str!("../../i18n/pt-BR.ftl"),
        Language::Fr => include_str!("../../i18n/fr.ftl"),
        Language::De => include_str!("../../i18n/de.ftl"),
        Language::Tr => include_str!("../../i18n/tr.ftl"),
        Language::Vi => include_str!("../../i18n/vi.ftl"),
        Language::Id => include_str!("../../i18n/id.ftl"),
        Language::Hi => include_str!("../../i18n/hi.ftl"),
    }
}

struct Catalog {
    lang: Language,
    bundle: FluentBundle<FluentResource>,
}

fn build(lang: Language) -> Catalog {
    let langid: unic_langid::LanguageIdentifier = lang
        .tag()
        .parse()
        .unwrap_or_else(|e| panic!("i18n: {}'s own tag does not parse: {e}", lang.tag()));
    let mut bundle = FluentBundle::new_concurrent(vec![langid]);
    // egui has no bidi engine; fluent's isolating marks (U+2068/U+2069) would paint as tofu boxes.
    bundle.set_use_isolating(false);

    let resource = match FluentResource::try_new(source(lang).to_string()) {
        Ok(resource) => resource,
        Err((resource, errors)) => {
            for error in &errors {
                tracing::error!(locale = lang.tag(), ?error, "i18n: catalog parse error");
            }
            resource
        }
    };
    if let Err(errors) = bundle.add_resource(resource) {
        for error in &errors {
            tracing::error!(
                locale = lang.tag(),
                ?error,
                "i18n: duplicate message id in catalog"
            );
        }
    }

    Catalog { lang, bundle }
}

static CATALOGS: OnceLock<Vec<Catalog>> = OnceLock::new();

fn catalogs() -> &'static [Catalog] {
    CATALOGS.get_or_init(|| {
        use strum::IntoEnumIterator;
        Language::iter().map(build).collect()
    })
}

fn find(lang: Language) -> &'static Catalog {
    catalogs()
        .iter()
        .find(|c| c.lang == lang)
        .unwrap_or_else(|| panic!("i18n: no catalog built for {}", lang.tag()))
}

/// Renders `key` in `lang`, falling back to English, then to the key id itself — never `""`
/// (test 11). Logs once at `error` on a total miss.
pub(crate) fn format(lang: Language, key: &str, args: Option<&FluentArgs>) -> String {
    format_inner(lang, key, args)
}

pub(crate) fn format_with_args(lang: Language, key: &str, args: &FluentArgs) -> String {
    format_inner(lang, key, Some(args))
}

/// One message entry as the guards need to see it: its id, its rendered value (with `{ $var }`
/// placeables left literal, i.e. the *source* text, not a rendering), and the set of variables it
/// references. Built by parsing the FTL source directly with `fluent-syntax` — independent of the
/// runtime `FluentBundle`, so a guard can inspect a catalog without formatting it. `cfg(test)`:
/// only the per-locale guards in `tests.rs` construct one.
#[cfg(test)]
pub(crate) struct ParsedMessage {
    pub id: String,
    /// The message's value, source lines joined with `\n` — comments and attributes excluded.
    pub value: String,
    pub variables: std::collections::BTreeSet<String>,
}

/// Parses `lang`'s catalog and returns every top-level message (not term) it declares, in file
/// order. A catalog that fails to parse returns whatever `fluent-syntax`'s error-recovering parser
/// could still salvage, plus the caller sees the same errors this module already logs at `error`.
#[cfg(test)]
pub(crate) fn parse_messages(lang: Language) -> Vec<ParsedMessage> {
    use fluent_syntax::ast::{Entry, PatternElement};

    let source = source(lang);
    let ast = match fluent_syntax::parser::parse(source) {
        Ok(ast) => ast,
        Err((ast, errors)) => {
            for error in &errors {
                tracing::error!(locale = lang.tag(), ?error, "i18n: catalog parse error");
            }
            ast
        }
    };

    ast.body
        .into_iter()
        .filter_map(|entry| match entry {
            Entry::Message(message) => Some(message),
            _ => None,
        })
        .filter_map(|message| {
            let pattern = message.value?;
            let mut value = String::new();
            let mut variables = std::collections::BTreeSet::new();
            for element in &pattern.elements {
                match element {
                    PatternElement::TextElement { value: text } => value.push_str(text),
                    PatternElement::Placeable { expression } => {
                        collect_variables(expression, &mut variables);
                        value.push_str("{…}");
                    }
                }
            }
            Some(ParsedMessage {
                id: message.id.name.to_string(),
                value,
                variables,
            })
        })
        .collect()
}

#[cfg(test)]
fn collect_variables(
    expr: &fluent_syntax::ast::Expression<&str>,
    out: &mut std::collections::BTreeSet<String>,
) {
    use fluent_syntax::ast::{Expression, InlineExpression};
    let visit_inline = |inline: &InlineExpression<&str>,
                        out: &mut std::collections::BTreeSet<String>| {
        if let InlineExpression::VariableReference { id } = inline {
            out.insert(id.name.to_string());
        }
    };
    match expr {
        Expression::Inline(inline) => visit_inline(inline, out),
        Expression::Select { selector, variants } => {
            visit_inline(selector, out);
            for variant in variants {
                for element in &variant.value.elements {
                    if let fluent_syntax::ast::PatternElement::Placeable { expression } = element {
                        collect_variables(expression, out);
                    }
                }
            }
        }
    }
}

fn format_inner(lang: Language, key: &str, args: Option<&FluentArgs>) -> String {
    for candidate in [lang, Language::En] {
        let catalog = find(candidate);
        let Some(message) = catalog.bundle.get_message(key) else {
            continue;
        };
        let Some(pattern) = message.value() else {
            continue;
        };
        let mut errors = Vec::new();
        let value = catalog.bundle.format_pattern(pattern, args, &mut errors);
        for error in &errors {
            tracing::error!(locale = candidate.tag(), key, ?error, "i18n: format error");
        }
        return value.into_owned();
    }
    tracing::error!(
        locale = lang.tag(),
        key,
        "i18n: key missing from every catalog"
    );
    key.to_string()
}
