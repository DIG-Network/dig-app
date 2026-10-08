//! Syn-based Rust-source scanning for the rewards guards (dig_ecosystem#3437).
//!
//! Several tests prove a property of PRODUCTION source -- "this call has exactly one caller", "no
//! test code names this key", "no hardcoded English in this builder". They used to cut test code
//! and comments out of the source with hand-rolled text scanners, and every scanner failed on the
//! next unusual input: a block comment quoting `#[cfg(test)]`, a raw string with a `}` in a test
//! module, a lone `"{"`. This module parses the file with `syn` instead, so comments are not
//! tokens at all, a raw string is one token, and "is this item test-only" is a question about an
//! attribute, not about bytes.
//!
//! # Compiled in two places
//!
//! `dig-app-core` declares it as `#[cfg(test)] mod source_scan;`, and the `dig-app` integration
//! test `reward_create_submit_has_one_production_caller.rs` includes the SAME file with
//! `#[path = "../../dig-app-core/src/rewards/source_scan.rs"] mod source_scan;` (a test crate
//! cannot reach another crate's test-only code). So nothing here may name `crate::` paths, and
//! each includer uses only a subset -- hence the file-level `allow(dead_code)`.
//!
//! # Failure direction
//!
//! A file `syn` cannot parse is an `Err` that names the problem; the caller's test fails on it.
//! Nothing here slices bytes or `expect`s on the shape of the input.
//!
//! # Macros
//!
//! `syn` leaves a macro body (`format!`, `assert!`, `matches!`) as raw tokens, so a plain AST walk
//! would MISS every call written inside one -- the fail-open direction for a "no other caller"
//! scan. Every counter below therefore walks the TOKEN STREAM of the node it is given, which
//! covers macro bodies exactly like ordinary code.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::Path;

use proc_macro2::{Delimiter, Spacing, TokenStream, TokenTree};
use quote::ToTokens;
use syn::ext::IdentExt;
use syn::visit::Visit;
use syn::visit_mut::VisitMut;
use syn::{
    punctuated::Punctuated, AttrStyle, Attribute, BinOp, Block, Expr, File, ImplItem, Item,
    ItemConst, ItemUse, Lit, Meta, Stmt, Token, TraitItem, UseTree, Visibility,
};

// ---------------------------------------------------------------------------------------------
// Parsing and pruning
// ---------------------------------------------------------------------------------------------

/// Parses `src` as a Rust file, keeping every item (test code included).
pub fn parse(src: &str) -> Result<File, String> {
    syn::parse_file(src).map_err(|e| format!("not parseable as Rust: {e}"))
}

/// `src` with every item that cannot exist in a non-test build removed: an item whose `#[cfg]` is
/// definitely false when `test` is false (see [`eval_cfg`]), any `#[test]` fn, and everything if
/// the file opens with `#![cfg(test)]`. Looks inside `mod`, `impl`, `trait` and block statements,
/// and also cuts a `#[cfg(test)]` match arm, struct or enum field, enum variant and struct-literal
/// field value.
pub fn production(src: &str) -> Result<File, String> {
    let mut file = parse(src)?;
    Prune { live: false }.visit_file_mut(&mut file);
    Ok(file)
}

/// [`production`], further without `use` items and without items marked `#[allow(dead_code)]`:
/// what is left is code that is actually reachable, so an identifier found in it is really
/// referenced. A name only imported, or only used inside a silenced dead builder, is not.
pub fn reachable(src: &str) -> Result<File, String> {
    let mut file = parse(src)?;
    Prune { live: true }.visit_file_mut(&mut file);
    Ok(file)
}

/// [`production`] for a test that has the file's path in hand: a parse error panics naming it.
pub fn production_at(path: &str, src: &str) -> File {
    production(src).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// [`reachable`] for a test that has the file's path in hand: a parse error panics naming it.
pub fn reachable_at(path: &str, src: &str) -> File {
    reachable(src).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// [`parse`] for a test that has the file's path in hand: a parse error panics naming it.
pub fn parse_at(path: &str, src: &str) -> File {
    parse(src).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Removes items from a tree. `live` additionally drops `use` items and dead-code-allowed items.
struct Prune {
    live: bool,
}

impl Prune {
    fn drops(&self, attrs: &[Attribute]) -> bool {
        attrs_mark_test_only(attrs) || (self.live && attrs_allow_dead_code(attrs))
    }

    fn drops_item(&self, item: &Item) -> bool {
        self.drops(item_attrs(item)) || (self.live && matches!(item, Item::Use(_)))
    }
}

impl VisitMut for Prune {
    fn visit_file_mut(&mut self, file: &mut File) {
        if attrs_mark_test_only(&file.attrs) {
            file.items.clear();
        }
        file.items.retain(|item| !self.drops_item(item));
        syn::visit_mut::visit_file_mut(self, file);
    }

    fn visit_item_mod_mut(&mut self, module: &mut syn::ItemMod) {
        if let Some((_, items)) = &mut module.content {
            items.retain(|item| !self.drops_item(item));
        }
        syn::visit_mut::visit_item_mod_mut(self, module);
    }

    fn visit_item_impl_mut(&mut self, imp: &mut syn::ItemImpl) {
        imp.items.retain(|item| !self.drops(impl_item_attrs(item)));
        syn::visit_mut::visit_item_impl_mut(self, imp);
    }

    fn visit_item_trait_mut(&mut self, tr: &mut syn::ItemTrait) {
        tr.items.retain(|item| !self.drops(trait_item_attrs(item)));
        syn::visit_mut::visit_item_trait_mut(self, tr);
    }

    fn visit_block_mut(&mut self, block: &mut Block) {
        block.stmts.retain(|stmt| match stmt {
            Stmt::Item(item) => !self.drops_item(item),
            Stmt::Local(local) => !self.drops(&local.attrs),
            Stmt::Macro(mac) => !self.drops(&mac.attrs),
            Stmt::Expr(expr, _) => !attrs_mark_test_only(expr_attrs(expr)),
        });
        syn::visit_mut::visit_block_mut(self, block);
    }

    // `#[cfg(test)]` is as valid on a match arm, a field, a variant or a struct-literal value as on
    // an item. These nodes are cut on the cfg alone: `#[allow(dead_code)]` on a field says nothing
    // about whether the thing it names is referenced.

    fn visit_expr_match_mut(&mut self, node: &mut syn::ExprMatch) {
        node.arms.retain(|arm| !attrs_mark_test_only(&arm.attrs));
        syn::visit_mut::visit_expr_match_mut(self, node);
    }

    fn visit_expr_struct_mut(&mut self, node: &mut syn::ExprStruct) {
        retain_live(&mut node.fields, |field| &field.attrs);
        syn::visit_mut::visit_expr_struct_mut(self, node);
    }

    fn visit_fields_named_mut(&mut self, fields: &mut syn::FieldsNamed) {
        retain_live(&mut fields.named, |field| &field.attrs);
        syn::visit_mut::visit_fields_named_mut(self, fields);
    }

    fn visit_fields_unnamed_mut(&mut self, fields: &mut syn::FieldsUnnamed) {
        retain_live(&mut fields.unnamed, |field| &field.attrs);
        syn::visit_mut::visit_fields_unnamed_mut(self, fields);
    }

    fn visit_item_enum_mut(&mut self, item: &mut syn::ItemEnum) {
        retain_live(&mut item.variants, |variant| &variant.attrs);
        syn::visit_mut::visit_item_enum_mut(self, item);
    }
}

/// Drops the elements of `list` whose attributes mark them test-only.
fn retain_live<T, P: Default>(list: &mut Punctuated<T, P>, attrs: impl Fn(&T) -> &[Attribute]) {
    let kept: Punctuated<T, P> = std::mem::take(list)
        .into_iter()
        .filter(|element| !attrs_mark_test_only(attrs(element)))
        .collect();
    *list = kept;
}

/// The outer attributes of an expression. `syn` offers no accessor for the 30-odd variants; a
/// variant not listed reads as attribute-free, so a `#[cfg(test)]` on it is KEPT (the safe side).
fn expr_attrs(expr: &Expr) -> &[Attribute] {
    match expr {
        Expr::Array(e) => &e.attrs,
        Expr::Assign(e) => &e.attrs,
        Expr::Async(e) => &e.attrs,
        Expr::Await(e) => &e.attrs,
        Expr::Binary(e) => &e.attrs,
        Expr::Block(e) => &e.attrs,
        Expr::Break(e) => &e.attrs,
        Expr::Call(e) => &e.attrs,
        Expr::Cast(e) => &e.attrs,
        Expr::Closure(e) => &e.attrs,
        Expr::Const(e) => &e.attrs,
        Expr::Continue(e) => &e.attrs,
        Expr::Field(e) => &e.attrs,
        Expr::ForLoop(e) => &e.attrs,
        Expr::Group(e) => &e.attrs,
        Expr::If(e) => &e.attrs,
        Expr::Index(e) => &e.attrs,
        Expr::Infer(e) => &e.attrs,
        Expr::Let(e) => &e.attrs,
        Expr::Lit(e) => &e.attrs,
        Expr::Loop(e) => &e.attrs,
        Expr::Macro(e) => &e.attrs,
        Expr::Match(e) => &e.attrs,
        Expr::MethodCall(e) => &e.attrs,
        Expr::Paren(e) => &e.attrs,
        Expr::Path(e) => &e.attrs,
        Expr::Range(e) => &e.attrs,
        Expr::Reference(e) => &e.attrs,
        Expr::Repeat(e) => &e.attrs,
        Expr::Return(e) => &e.attrs,
        Expr::Struct(e) => &e.attrs,
        Expr::Try(e) => &e.attrs,
        Expr::TryBlock(e) => &e.attrs,
        Expr::Tuple(e) => &e.attrs,
        Expr::Unary(e) => &e.attrs,
        Expr::Unsafe(e) => &e.attrs,
        Expr::While(e) => &e.attrs,
        Expr::Yield(e) => &e.attrs,
        _ => &[],
    }
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::ExternCrate(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::ForeignMod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::TraitAlias(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Union(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

fn impl_item_attrs(item: &ImplItem) -> &[Attribute] {
    match item {
        ImplItem::Const(i) => &i.attrs,
        ImplItem::Fn(i) => &i.attrs,
        ImplItem::Type(i) => &i.attrs,
        ImplItem::Macro(i) => &i.attrs,
        _ => &[],
    }
}

fn trait_item_attrs(item: &TraitItem) -> &[Attribute] {
    match item {
        TraitItem::Const(i) => &i.attrs,
        TraitItem::Fn(i) => &i.attrs,
        TraitItem::Type(i) => &i.attrs,
        TraitItem::Macro(i) => &i.attrs,
        _ => &[],
    }
}

/// True if any attribute is a `#[test]` or a `#[cfg(..)]` that is definitely false in a non-test
/// build. Inner attributes count, so `#![cfg(test)]` at the top of a file or `mod` is found.
fn attrs_mark_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if attr.path().is_ident("test") {
            return true;
        }
        if !attr.path().is_ident("cfg") {
            return false;
        }
        // A predicate this cannot parse is UNKNOWN, so the item is kept: wrongly keeping a test
        // item is a nuisance, wrongly deleting production code is silent corruption.
        attr.parse_args::<Meta>()
            .map(|meta| eval_cfg(&meta) == Tri::False)
            .unwrap_or(false)
    })
}

/// True if an OUTER attribute is `#[allow(.., dead_code, ..)]`. An inner `#![allow(dead_code)]`
/// silences a whole scope, not the item that happens to contain it, so it does not count.
fn attrs_allow_dead_code(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !matches!(attr.style, AttrStyle::Outer) || !attr.path().is_ident("allow") {
            return false;
        }
        attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .map(|lints| lints.iter().any(|lint| lint.path().is_ident("dead_code")))
            .unwrap_or(false)
    })
}

// ---------------------------------------------------------------------------------------------
// `#[cfg]` predicates: three-valued (Kleene) logic
// ---------------------------------------------------------------------------------------------

/// Truth of a `#[cfg(..)]` predicate in a NON-test build, where every atom but `test` may or may
/// not hold in some real build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tri {
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

/// Kleene AND: false if any operand is false, true if all are true, else unknown.
fn tri_all(values: impl Iterator<Item = Tri>) -> Tri {
    let mut all_true = true;
    for value in values {
        match value {
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

/// Kleene OR: true if any operand is true, false if all are false, else unknown.
fn tri_any(values: impl Iterator<Item = Tri>) -> Tri {
    let mut all_false = true;
    for value in values {
        match value {
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

/// Evaluates a cfg predicate asking "does this hold in a production (non-test) build". `test` is
/// definitely false; any other atom (`unix`, `feature = "x"`) is unknown; `not`/`all`/`any`
/// combine per Kleene logic. An item is removed only when this is [`Tri::False`] -- "unknown"
/// means it might compile in production, so it stays. A malformed `not`/`all`/`any` is unknown.
pub fn eval_cfg(meta: &Meta) -> Tri {
    match meta {
        Meta::Path(path) if path.is_ident("test") => Tri::False,
        Meta::List(list) => {
            let Ok(args) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            else {
                return Tri::Unknown;
            };
            if list.path.is_ident("not") && args.len() == 1 {
                eval_cfg(&args[0]).negate()
            } else if list.path.is_ident("all") {
                tri_all(args.iter().map(eval_cfg))
            } else if list.path.is_ident("any") {
                tri_any(args.iter().map(eval_cfg))
            } else {
                Tri::Unknown
            }
        }
        _ => Tri::Unknown,
    }
}

/// [`eval_cfg`] over predicate text such as `all(test, unix)`; text that is not a valid cfg
/// predicate is [`Tri::Unknown`].
pub fn eval_cfg_text(predicate: &str) -> Tri {
    syn::parse_str::<Meta>(predicate)
        .map(|meta| eval_cfg(&meta))
        .unwrap_or(Tri::Unknown)
}

// ---------------------------------------------------------------------------------------------
// Token-stream scan: calls, identifiers, string literals
// ---------------------------------------------------------------------------------------------

/// A call site: `a::b::f(args)` (path `["a","b","f"]`) or `.m(args)` (path `["m"]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// The path segments before the argument list.
    pub path: Vec<String>,
    /// Each top-level, comma-separated argument as its token strings, e.g. `&X` is `["&", "X"]`.
    pub args: Vec<Vec<String>>,
}

#[derive(Default)]
struct Scan {
    calls: Vec<Call>,
    methods: Vec<Call>,
    /// Every path written anywhere -- called or not -- except the name a `fn` declares.
    paths: Vec<Vec<String>>,
    idents: BTreeSet<String>,
    literals: Vec<String>,
}

fn scan(node: &impl ToTokens) -> Scan {
    let mut scan = Scan::default();
    scan.walk(node.to_token_stream());
    scan
}

impl Scan {
    fn walk(&mut self, stream: TokenStream) {
        let tokens: Vec<TokenTree> = stream.into_iter().collect();
        self.walk_tokens(&tokens);
    }

    fn walk_tokens(&mut self, tokens: &[TokenTree]) {
        let mut at = 0;
        while at < tokens.len() {
            at = self.step(tokens, at);
        }
    }

    /// Consumes the token at `at` (and whatever belongs with it), returning the next index.
    fn step(&mut self, tokens: &[TokenTree], at: usize) -> usize {
        match &tokens[at] {
            TokenTree::Punct(p) if p.as_char() == '#' => {
                attribute_end(tokens, at).unwrap_or(at + 1)
            }
            TokenTree::Punct(_) => at + 1,
            TokenTree::Ident(_) => self.path_or_ident(tokens, at),
            TokenTree::Group(group) => {
                self.walk(group.stream());
                at + 1
            }
            TokenTree::Literal(literal) => {
                if let Lit::Str(text) = Lit::new(literal.clone()) {
                    self.literals.push(text.value());
                }
                at + 1
            }
        }
    }

    /// Reads `a::b::c` (and `a::b::<T>::c`) starting at `at`, records every segment as an
    /// identifier, the whole path as a reference and, when an argument list follows, a call.
    /// Returns the index of the token after the path, so the argument group is walked next as
    /// ordinary tokens (nested calls are found).
    ///
    /// A turbofish is skipped over (its tokens are still walked), and a raw identifier is the
    /// name without its `r#`: `create_card::r#submit::<D>(x)` is a call of `create_card::submit`.
    fn path_or_ident(&mut self, tokens: &[TokenTree], at: usize) -> usize {
        let mut path = vec![name_of(&tokens[at])];
        let mut last = at;
        while is_path_separator(tokens, last + 1) {
            match tokens.get(last + 3) {
                Some(TokenTree::Ident(next)) => {
                    path.push(name_of_ident(next));
                    last += 3;
                }
                Some(TokenTree::Punct(open)) if open.as_char() == '<' => {
                    let Some(close) = generic_args_end(tokens, last + 3) else {
                        break;
                    };
                    self.walk_tokens(&tokens[last + 4..close]);
                    last = close;
                }
                _ => break,
            }
        }
        self.idents.extend(path.iter().cloned());
        let declares_it = previous_is_ident(tokens, at, "fn");
        if !declares_it {
            self.paths.push(path.clone());
        }

        let Some(TokenTree::Group(args)) = tokens.get(last + 1) else {
            return last + 1;
        };
        if args.delimiter() != Delimiter::Parenthesis || declares_it {
            return last + 1;
        }
        let call = Call {
            path: path.clone(),
            args: split_args(args.stream()),
        };
        match at.checked_sub(1).map(|prev| &tokens[prev]) {
            Some(TokenTree::Punct(dot)) if dot.as_char() == '.' && path.len() == 1 => {
                self.methods.push(call)
            }
            Some(TokenTree::Punct(dot)) if dot.as_char() == '.' => {}
            _ => self.calls.push(call),
        }
        last + 1
    }
}

/// The name an identifier token spells, without a raw-identifier `r#`.
fn name_of(token: &TokenTree) -> String {
    match token {
        TokenTree::Ident(ident) => name_of_ident(ident),
        other => other.to_string(),
    }
}

fn name_of_ident(ident: &proc_macro2::Ident) -> String {
    ident.unraw().to_string()
}

/// `tokens[open]` is the `<` of a turbofish: the index of its balancing `>`, or `None` if it never
/// closes. `>>` is two `>` tokens, and the `>` of `->` / `=>` closes nothing.
fn generic_args_end(tokens: &[TokenTree], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        let TokenTree::Punct(punct) = token else {
            continue;
        };
        match punct.as_char() {
            '<' => depth += 1,
            '>' if !closes_an_arrow(tokens, index) => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// True if `tokens[index]` is the `>` of a `->` or `=>`.
fn closes_an_arrow(tokens: &[TokenTree], index: usize) -> bool {
    let Some(prev) = index.checked_sub(1) else {
        return false;
    };
    matches!(
        &tokens[prev],
        TokenTree::Punct(p) if matches!(p.as_char(), '-' | '=') && p.spacing() == Spacing::Joint
    )
}

/// True if `tokens[at]` and `tokens[at + 1]` are the two colons of a `::`.
fn is_path_separator(tokens: &[TokenTree], at: usize) -> bool {
    let colon =
        |index: usize| matches!(tokens.get(index), Some(TokenTree::Punct(p)) if p.as_char() == ':');
    colon(at) && colon(at + 1)
}

fn previous_is_ident(tokens: &[TokenTree], at: usize, word: &str) -> bool {
    at.checked_sub(1)
        .is_some_and(|prev| matches!(&tokens[prev], TokenTree::Ident(i) if i == word))
}

/// If an attribute (`#[..]` or `#![..]`) starts at `at`, the index just past it.
fn attribute_end(tokens: &[TokenTree], at: usize) -> Option<usize> {
    let bang = matches!(tokens.get(at + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!');
    let body = at + 1 + usize::from(bang);
    match tokens.get(body) {
        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Bracket => Some(body + 1),
        _ => None,
    }
}

fn split_args(stream: TokenStream) -> Vec<Vec<String>> {
    let mut args: Vec<Vec<String>> = vec![Vec::new()];
    for token in stream {
        match &token {
            TokenTree::Punct(p) if p.as_char() == ',' => args.push(Vec::new()),
            other => args
                .last_mut()
                .expect("args starts non-empty")
                .push(other.to_string()),
        }
    }
    if args.last().is_some_and(Vec::is_empty) {
        args.pop();
    }
    args
}

/// Every path call (`a::f(..)`, `f(..)`) in `node`, macro bodies included.
pub fn path_calls(node: &impl ToTokens) -> Vec<Call> {
    scan(node).calls
}

/// Every method call (`.m(..)`) in `node`, macro bodies included.
pub fn method_calls(node: &impl ToTokens) -> Vec<Call> {
    scan(node).methods
}

/// How many path calls in `node` end in `path` (`"create_card::submit"` also matches
/// `crate::rewards::create_card::submit(..)`, but not `my_create_card::submit(..)`).
pub fn count_path_calls(node: &impl ToTokens, path: &str) -> usize {
    let wanted: Vec<&str> = path.split("::").collect();
    path_calls(node)
        .iter()
        .filter(|call| ends_with_path(&call.path, &wanted))
        .count()
}

/// How many times `node` WRITES a path ending in `path`, called or not: `f(..)`, `let g = f;`,
/// `.map(a::f)`, `use a::f as h;`, `run!(a::f)`. A declaration (`fn f`) is not a reference. A
/// "sole caller" guard that requires references == calls refuses every way of reaching `f`
/// without calling it by name.
pub fn count_path_references(node: &impl ToTokens, path: &str) -> usize {
    let wanted: Vec<&str> = path.split("::").collect();
    scan(node)
        .paths
        .iter()
        .filter(|written| ends_with_path(written, &wanted))
        .count()
}

fn ends_with_path(written: &[String], wanted: &[&str]) -> bool {
    written.len() >= wanted.len()
        && written[written.len() - wanted.len()..]
            .iter()
            .zip(wanted)
            .all(|(a, b)| a == b)
}

/// How many calls to something named `name` `node` contains, whichever way it is written:
/// `name(..)`, `a::b::name(..)` or `.name(..)`; macro bodies included.
pub fn count_calls_named(node: &impl ToTokens, name: &str) -> usize {
    count_path_calls(node, name) + count_method_calls(node, name)
}

/// How many `.name(..)` method calls `node` contains, macro bodies included.
pub fn count_method_calls(node: &impl ToTokens, name: &str) -> usize {
    method_calls(node)
        .iter()
        .filter(|call| call.path[0] == name)
        .count()
}

/// Every identifier in `node`, macro bodies included, attributes (and so doc comments) excluded.
pub fn idents(node: &impl ToTokens) -> BTreeSet<String> {
    scan(node).idents
}

/// Every string literal in `node` with escapes and raw strings resolved, macro bodies included
/// (a `format!("..")` literal counts), attributes -- so doc comments -- excluded.
pub fn string_literals(node: &impl ToTokens) -> Vec<String> {
    scan(node).literals
}

/// `node`'s tokens as one string with all whitespace removed, for comparing code shapes without
/// caring how it was formatted (`Feed::app().begin(x)` whatever the spacing).
pub fn normalized(node: &impl ToTokens) -> String {
    squash(&node.to_token_stream().to_string())
}

/// `text` with all whitespace removed -- the same form [`normalized`] returns.
pub fn squash(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

// ---------------------------------------------------------------------------------------------
// Structural queries
// ---------------------------------------------------------------------------------------------

/// The body of the first `fn name` anywhere in `file` -- a free fn, a nested fn or a method.
pub fn fn_named(file: &File, name: &str) -> Option<Block> {
    let mut finder = FnFinder { name, found: None };
    finder.visit_file(file);
    finder.found
}

struct FnFinder<'a> {
    name: &'a str,
    found: Option<Block>,
}

impl<'ast> Visit<'ast> for FnFinder<'_> {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if self.found.is_none() && f.sig.ident == self.name {
            self.found = Some((*f.block).clone());
        } else {
            syn::visit::visit_item_fn(self, f);
        }
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        if self.found.is_none() && f.sig.ident == self.name {
            self.found = Some(f.block.clone());
        } else {
            syn::visit::visit_impl_item_fn(self, f);
        }
    }
}

/// Every top-level or module-level `const` item in `file`.
pub fn consts(file: &File) -> Vec<ItemConst> {
    struct Consts(Vec<ItemConst>);
    impl<'ast> Visit<'ast> for Consts {
        fn visit_item_const(&mut self, c: &'ast ItemConst) {
            self.0.push(c.clone());
        }
    }
    let mut found = Consts(Vec::new());
    found.visit_file(file);
    found.0
}

/// The `then` blocks of every `if let <pattern> = <scrutinee> { .. }` in `file`, matched on the
/// two parts' normalized text (`"Some(shown)"`, `"shown"`).
pub fn if_let_blocks(file: &File, pattern: &str, scrutinee: &str) -> Vec<Block> {
    struct IfLets {
        pattern: String,
        scrutinee: String,
        found: Vec<Block>,
    }
    impl<'ast> Visit<'ast> for IfLets {
        fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
            if let Expr::Let(cond) = &*node.cond {
                if normalized(&*cond.pat) == self.pattern
                    && normalized(&*cond.expr) == self.scrutinee
                {
                    self.found.push(node.then_branch.clone());
                }
            }
            syn::visit::visit_expr_if(self, node);
        }
    }
    let mut finder = IfLets {
        pattern: squash(pattern),
        scrutinee: squash(scrutinee),
        found: Vec::new(),
    };
    finder.visit_file(file);
    finder.found
}

/// How many `<left> && <right>` expressions `file` contains, matched on normalized text.
pub fn count_and_conditions(file: &File, left: &str, right: &str) -> usize {
    struct Ands {
        left: String,
        right: String,
        count: usize,
    }
    impl<'ast> Visit<'ast> for Ands {
        fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
            if matches!(node.op, BinOp::And(_))
                && normalized(&*node.left) == self.left
                && normalized(&*node.right) == self.right
            {
                self.count += 1;
            }
            syn::visit::visit_expr_binary(self, node);
        }
    }
    let mut finder = Ands {
        left: squash(left),
        right: squash(right),
        count: 0,
    };
    finder.visit_file(file);
    finder.count
}

// ---------------------------------------------------------------------------------------------
// Walking the workspace
// ---------------------------------------------------------------------------------------------

/// Every `.rs` file under `dir` as `(path, source)`, read at test time (the file set is not
/// knowable at compile time). `target/` is skipped -- build output, never source. Panics, naming
/// the cause, when [`try_workspace_rust_sources`] fails.
pub fn workspace_rust_sources(dir: &Path) -> Vec<(String, String)> {
    try_workspace_rust_sources(dir).unwrap_or_else(|e| panic!("{e}"))
}

/// [`workspace_rust_sources`] as a `Result`. Fails, naming the path, on anything it cannot read --
/// a directory, an entry, a file: a scan that silently skips an unreadable file would pass every
/// "no other caller" assertion about it. Fails too when the walk finds 20 files or fewer: a scan
/// over a silently empty set would pass for the worst possible reason.
pub fn try_workspace_rust_sources(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let mut files = Vec::new();
    collect_rust_files(dir, &mut files)?;
    if files.len() <= 20 {
        return Err(format!(
            "workspace_rust_sources walked only {} files under {} (it needs more than 20) -- the \
             walk is broken, not the codebase",
            files.len(),
            dir.display()
        ));
    }
    Ok(files)
}

fn collect_rust_files(dir: &Path, out: &mut Vec<(String, String)>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read directory {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry
            .map_err(|e| format!("cannot read an entry of directory {}: {e}", dir.display()))?;
        let path = entry.path();
        let is_dir = std::fs::metadata(&path)
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?
            .is_dir();
        if is_dir {
            if path.file_name().and_then(|n| n.to_str()) != Some("target") {
                collect_rust_files(&path, out)?;
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let src = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            out.push((path.display().to_string(), src));
        }
    }
    Ok(())
}

/// True if `path` (a file the walk of `root` returned) is an integration-test crate: it has a
/// `tests/` directory BELOW `root`. Such a file carries no `#[cfg(test)]` marker (the whole file IS
/// the test crate), so pruning cannot cut it and every line would otherwise read as production.
/// Only the part under `root` is searched: a checkout that itself lives under some `tests/`
/// directory must not turn every production file into a test file. A path not under `root` is
/// not a test file (it is scanned).
pub fn is_integration_test_file(root: &Path, path: &str) -> bool {
    let Ok(below_root) = Path::new(path).strip_prefix(root) else {
        return false;
    };
    format!("/{}", below_root.to_string_lossy().replace('\\', "/")).contains("/tests/")
}

// ---------------------------------------------------------------------------------------------
// Reaching a module's item: references and `use` trees
// ---------------------------------------------------------------------------------------------

/// Every way a file reaches `module::item`, for a sole-caller guard (dig_ecosystem#3437).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ModuleItemUses {
    /// Paths written that end in `module::item` (or `<alias>::item` for a local rename of
    /// `module`), called or not.
    pub references: usize,
    /// The subset of those that are calls.
    pub calls: usize,
    /// `use` trees that make the item reachable under a name no path scan can follow: importing
    /// the item (renamed or not), globbing the module, or PUBLICLY renaming the module.
    pub escapes: Vec<String>,
}

/// How `file` reaches `module::item`: see [`ModuleItemUses`]. Names are NOT resolved -- there is
/// no type information, so this is a guard on spelling, not a call graph. What it does not
/// follow, by design: a call through a bound value, `(d.begin)(x)`.
///
/// A local `use a::module as cc;` is followed within the file (`cc::item` counts as
/// `module::item`); `use a::module::item;`, `use a::module::*;` and a public rename of `module`
/// are reported as escapes instead, because the bare name they introduce cannot be told from any
/// other.
pub fn module_item_uses(file: &File, module: &str, item: &str) -> ModuleItemUses {
    let mut trees = UseTrees {
        module,
        item,
        aliases: BTreeSet::new(),
        escapes: Vec::new(),
    };
    trees.visit_file(file);

    let mut names = trees.aliases;
    names.insert(module.to_string());
    let mut uses = ModuleItemUses {
        escapes: trees.escapes,
        ..ModuleItemUses::default()
    };
    for name in names {
        let path = format!("{name}::{item}");
        uses.references += count_path_references(file, &path);
        uses.calls += count_path_calls(file, &path);
    }
    uses
}

/// Collects, from every `use` item, the local names given to a module and the `use` trees that
/// escape a path scan.
struct UseTrees<'a> {
    module: &'a str,
    item: &'a str,
    aliases: BTreeSet<String>,
    escapes: Vec<String>,
}

impl UseTrees<'_> {
    /// `in_module`: the segment just before this tree is the module itself.
    fn tree(&mut self, tree: &UseTree, in_module: bool, public: bool) {
        match tree {
            UseTree::Path(path) => {
                let is_module = path.ident.unraw() == self.module;
                self.tree(&path.tree, is_module, public);
            }
            UseTree::Name(name) => {
                if in_module && name.ident.unraw() == self.item {
                    self.escapes
                        .push(format!("imports `{}::{}`", self.module, self.item));
                }
            }
            UseTree::Rename(rename) => {
                let name = rename.ident.unraw().to_string();
                if in_module && name == self.item {
                    self.escapes.push(format!(
                        "imports `{}::{}` under a new name",
                        self.module, self.item
                    ));
                } else if name == self.module || (in_module && name == "self") {
                    let alias = rename.rename.unraw().to_string();
                    self.aliases.insert(alias.clone());
                    if public {
                        self.escapes.push(format!(
                            "publicly re-exports `{}` as `{alias}`",
                            self.module
                        ));
                    }
                }
            }
            UseTree::Glob(_) => {
                if in_module {
                    self.escapes.push(format!("globs `{}::*`", self.module));
                }
            }
            UseTree::Group(group) => {
                for inner in &group.items {
                    self.tree(inner, in_module, public);
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for UseTrees<'_> {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        let public = !matches!(node.vis, Visibility::Inherited);
        self.tree(&node.tree, false, public);
    }
}
