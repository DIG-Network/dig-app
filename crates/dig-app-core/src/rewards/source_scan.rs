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

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::ToTokens;
use syn::visit::Visit;
use syn::visit_mut::VisitMut;
use syn::{
    punctuated::Punctuated, AttrStyle, Attribute, BinOp, Block, Expr, File, ImplItem, Item,
    ItemConst, Lit, Meta, Stmt, Token, TraitItem,
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
/// the file opens with `#![cfg(test)]`. Looks inside `mod`, `impl`, `trait` and block statements.
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
            Stmt::Expr(..) => true,
        });
        syn::visit_mut::visit_block_mut(self, block);
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
        let mut at = 0;
        while at < tokens.len() {
            at = self.step(&tokens, at);
        }
    }

    /// Consumes the token at `at` (and whatever belongs with it), returning the next index.
    fn step(&mut self, tokens: &[TokenTree], at: usize) -> usize {
        match &tokens[at] {
            TokenTree::Punct(p) if p.as_char() == '#' => attribute_end(tokens, at).unwrap_or(at + 1),
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

    /// Reads `a::b::c` starting at `at`, records every segment as an identifier and, when an
    /// argument list follows, a call. Returns the index of the token after the path, so the
    /// argument group is walked next as ordinary tokens (nested calls are found).
    fn path_or_ident(&mut self, tokens: &[TokenTree], at: usize) -> usize {
        let mut path = vec![tokens[at].to_string()];
        let mut last = at;
        while is_path_separator(tokens, last + 1) {
            let Some(TokenTree::Ident(next)) = tokens.get(last + 3) else {
                break;
            };
            path.push(next.to_string());
            last += 3;
        }
        self.idents.extend(path.iter().cloned());

        let Some(TokenTree::Group(args)) = tokens.get(last + 1) else {
            return last + 1;
        };
        if args.delimiter() != Delimiter::Parenthesis || previous_is_ident(tokens, at, "fn") {
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

/// True if `tokens[at]` and `tokens[at + 1]` are the two colons of a `::`.
fn is_path_separator(tokens: &[TokenTree], at: usize) -> bool {
    let colon = |index: usize| matches!(tokens.get(index), Some(TokenTree::Punct(p)) if p.as_char() == ':');
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
            other => args.last_mut().expect("args starts non-empty").push(other.to_string()),
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
        .filter(|call| call.path.len() >= wanted.len() && call.path.ends_with_str(&wanted))
        .count()
}

/// How many `.name(..)` method calls `node` contains, macro bodies included.
pub fn count_method_calls(node: &impl ToTokens, name: &str) -> usize {
    method_calls(node).iter().filter(|call| call.path[0] == name).count()
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

trait EndsWithStr {
    fn ends_with_str(&self, wanted: &[&str]) -> bool;
}

impl EndsWithStr for Vec<String> {
    fn ends_with_str(&self, wanted: &[&str]) -> bool {
        self[self.len() - wanted.len()..].iter().zip(wanted).all(|(a, b)| a == b)
    }
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
    struct IfLets<'a> {
        pattern: String,
        scrutinee: String,
        found: Vec<Block>,
        _marker: std::marker::PhantomData<&'a ()>,
    }
    impl<'ast> Visit<'ast> for IfLets<'_> {
        fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
            if let Expr::Let(cond) = &*node.cond {
                if normalized(&*cond.pat) == self.pattern && normalized(&*cond.expr) == self.scrutinee {
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
        _marker: std::marker::PhantomData,
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
/// knowable at compile time). `target/` is skipped -- build output, never source. Panics if the
/// walk finds 20 files or fewer: a scan over a silently empty set would pass every "no other
/// caller" assertion for the worst possible reason.
pub fn workspace_rust_sources(dir: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    collect_rust_files(dir, &mut files);
    assert!(
        files.len() > 20,
        "workspace_rust_sources walked only {} files under {} -- the walk is broken, not the \
         codebase",
        files.len(),
        dir.display()
    );
    files
}

fn collect_rust_files(dir: &Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) != Some("target") {
                collect_rust_files(&path, out);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(src) = std::fs::read_to_string(&path) {
                out.push((path.display().to_string(), src));
            }
        }
    }
}
