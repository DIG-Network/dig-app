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
//!
//! Three limits follow from that, all accepted (dig_ecosystem#3462; the scanner this replaced had
//! the first two too): a `macro_rules!` whose body wraps a guarded call counts ONCE per
//! definition, not once per invocation; a `#[cfg(test)]` item written inside a macro invocation
//! body, `m! { #[cfg(test)] fn x() {} }`, is not pruned (both need macro expansion; pinned by an
//! `#[ignore]`d test); and a call through a bound value, `(d.begin)(x)`, is not a call because
//! the scan is on names and there are no types. A UFCS call `Type::begin(..)` IS seen by
//! `path_calls`, `count_calls_named` and `count_path_references`; only `count_method_calls`
//! misses it, so a guard that must see every caller counts references.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
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
/// and also cuts a `#[cfg(test)]` match arm, struct or enum field, enum variant, struct-literal
/// field value, call or method-call argument, array or tuple element, closure parameter, fn
/// parameter, generic parameter and foreign-mod item.
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

    fn visit_expr_call_mut(&mut self, node: &mut syn::ExprCall) {
        retain_live(&mut node.args, expr_attrs);
        syn::visit_mut::visit_expr_call_mut(self, node);
    }

    fn visit_expr_method_call_mut(&mut self, node: &mut syn::ExprMethodCall) {
        retain_live(&mut node.args, expr_attrs);
        syn::visit_mut::visit_expr_method_call_mut(self, node);
    }

    fn visit_expr_array_mut(&mut self, node: &mut syn::ExprArray) {
        retain_live(&mut node.elems, expr_attrs);
        syn::visit_mut::visit_expr_array_mut(self, node);
    }

    fn visit_expr_tuple_mut(&mut self, node: &mut syn::ExprTuple) {
        retain_live(&mut node.elems, expr_attrs);
        syn::visit_mut::visit_expr_tuple_mut(self, node);
    }

    fn visit_expr_closure_mut(&mut self, node: &mut syn::ExprClosure) {
        retain_live(&mut node.inputs, pat_attrs);
        syn::visit_mut::visit_expr_closure_mut(self, node);
    }

    fn visit_signature_mut(&mut self, sig: &mut syn::Signature) {
        retain_live(&mut sig.inputs, fn_arg_attrs);
        syn::visit_mut::visit_signature_mut(self, sig);
    }

    fn visit_generics_mut(&mut self, generics: &mut syn::Generics) {
        retain_live(&mut generics.params, generic_param_attrs);
        syn::visit_mut::visit_generics_mut(self, generics);
    }

    fn visit_item_foreign_mod_mut(&mut self, node: &mut syn::ItemForeignMod) {
        node.items
            .retain(|item| !attrs_mark_test_only(foreign_item_attrs(item)));
        syn::visit_mut::visit_item_foreign_mod_mut(self, node);
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

/// The outer attributes of a closure parameter pattern. A variant not listed reads as
/// attribute-free, so a `#[cfg(test)]` on it is KEPT (the safe side).
fn pat_attrs(pat: &syn::Pat) -> &[Attribute] {
    use syn::Pat;
    match pat {
        Pat::Const(p) => &p.attrs,
        Pat::Ident(p) => &p.attrs,
        Pat::Lit(p) => &p.attrs,
        Pat::Macro(p) => &p.attrs,
        Pat::Or(p) => &p.attrs,
        Pat::Paren(p) => &p.attrs,
        Pat::Path(p) => &p.attrs,
        Pat::Range(p) => &p.attrs,
        Pat::Reference(p) => &p.attrs,
        Pat::Rest(p) => &p.attrs,
        Pat::Slice(p) => &p.attrs,
        Pat::Struct(p) => &p.attrs,
        Pat::Tuple(p) => &p.attrs,
        Pat::TupleStruct(p) => &p.attrs,
        Pat::Type(p) => &p.attrs,
        Pat::Wild(p) => &p.attrs,
        _ => &[],
    }
}

/// The outer attributes of a fn parameter, `self` receiver included.
fn fn_arg_attrs(arg: &syn::FnArg) -> &[Attribute] {
    match arg {
        syn::FnArg::Receiver(r) => &r.attrs,
        syn::FnArg::Typed(p) => &p.attrs,
    }
}

/// The outer attributes of a lifetime, type or const generic parameter.
fn generic_param_attrs(param: &syn::GenericParam) -> &[Attribute] {
    match param {
        syn::GenericParam::Lifetime(p) => &p.attrs,
        syn::GenericParam::Type(p) => &p.attrs,
        syn::GenericParam::Const(p) => &p.attrs,
    }
}

/// The outer attributes of an item inside an `extern` block.
fn foreign_item_attrs(item: &syn::ForeignItem) -> &[Attribute] {
    match item {
        syn::ForeignItem::Fn(i) => &i.attrs,
        syn::ForeignItem::Static(i) => &i.attrs,
        syn::ForeignItem::Type(i) => &i.attrs,
        syn::ForeignItem::Macro(i) => &i.attrs,
        _ => &[],
    }
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

/// Binds every reference to `path` that `file` writes to exactly one named exception, or says why
/// not. Each shape is a Rust EXPRESSION naming `path` exactly once (e.g. `"feed.begin(opening)"`,
/// `"!self.begin()"`). It is matched against the parsed tree's expressions by normalized token text,
/// never against file text, so a string literal or doc comment holding the shape matches nothing.
/// The outermost matching expression is bound and not descended into, so one reference can never
/// satisfy two nested shapes. Ok only if every shape is bound exactly as often as it is listed and
/// the file's references (`count_path_references`) equal the bound count. A reference inside a macro
/// body is counted but can never be bound (syn does not parse macro bodies): it fails closed.
pub fn bind_references(file: &File, path: &str, shapes: &[&str]) -> Result<(), String> {
    let mut wanted: BTreeMap<String, ListedShape> = BTreeMap::new();
    for shape in shapes {
        let expr: Expr = syn::parse_str(shape)
            .map_err(|e| format!("exception {shape:?} is not a Rust expression: {e}"))?;
        let named = count_path_references(&expr, path);
        if named != 1 {
            return Err(format!(
                "exception {shape:?} names `{path}` {named} times; an exception excuses exactly one reference"
            ));
        }
        wanted
            .entry(normalized(&expr))
            .or_insert_with(|| ListedShape {
                shape: (*shape).to_string(),
                listed: 0,
            })
            .listed += 1;
    }

    let mut binder = Binder {
        wanted: &wanted,
        bound: BTreeMap::new(),
    };
    binder.visit_file(file);
    for (key, listed) in &wanted {
        let matched = binder.bound.get(key).copied().unwrap_or(0);
        if matched != listed.listed {
            return Err(format!(
                "exception {:?} is listed {} time(s) but matches {matched} expression(s) -- stale or duplicated exemption",
                listed.shape, listed.listed
            ));
        }
    }

    let bound: usize = wanted.values().map(|listed| listed.listed).sum();
    let references = count_path_references(file, path);
    if references != bound {
        return Err(format!(
            "names `{path}` {references} time(s); only {bound} are bound to a named exception"
        ));
    }
    Ok(())
}

/// One exception as written by the caller, and how many times it was listed.
struct ListedShape {
    shape: String,
    listed: usize,
}

/// Counts, per normalized shape, the expressions of a tree that match it.
struct Binder<'a> {
    wanted: &'a BTreeMap<String, ListedShape>,
    bound: BTreeMap<String, usize>,
}

impl<'ast> Visit<'ast> for Binder<'_> {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        let key = normalized(expr);
        if self.wanted.contains_key(&key) {
            // Outermost match wins and is not descended: one bound expression, one reference.
            *self.bound.entry(key).or_default() += 1;
            return;
        }
        syn::visit::visit_expr(self, expr);
    }
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
/// knowable at compile time). Cargo's build output (see [`is_build_output_dir`]) is skipped -- never source. Panics, naming
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
    collect_rust_files(dir, dir, &mut files)?;
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

/// THE walk's predicate for "this is a Rust source file": `collect_rust_files` reads exactly the
/// files for which this is true, and `walk_reads_as_production` uses it too, so a manifest or
/// `#[path]` target cannot pass the guard while the walk skips it. A file named exactly `.rs` has
/// no extension in Rust, so it is NOT walked (dig_ecosystem#3478).
pub fn is_walked_rust_file(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("rs")
}

fn collect_rust_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, String)>,
) -> Result<(), String> {
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
            if !is_build_output_dir(root, &path) {
                collect_rust_files(root, &path, out)?;
            }
        } else if is_walked_rust_file(&path) {
            let src = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            out.push((path.display().to_string(), src));
        }
    }
    Ok(())
}

/// True when `dir` is where Cargo writes build output for the walk of `root`:
/// `<root>/<package>/target` (a package built on its own). The workspace's own `target/` lives at
/// the repo root, outside the walked `crates/` root, so `<root>/target` is a PACKAGE named `target`
/// and is walked. A `target` directory anywhere deeper -- `<package>/src/target/` -- is source, so the walk scans it. Both separators
/// are accepted on every OS (normalised before the prefix is stripped). Shared by the walk and by
/// [`source_escapes`], so the two cannot disagree about what is skipped.
pub fn is_build_output_dir(root: &Path, dir: &Path) -> bool {
    let root = root.to_string_lossy().replace('\\', "/");
    let dir = dir.to_string_lossy().replace('\\', "/");
    let Ok(below_root) = Path::new(&dir).strip_prefix(&root) else {
        return false;
    };
    let below_root = below_root.to_string_lossy();
    let parts: Vec<&str> = below_root
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    matches!(parts.as_slice(), [_, "target"])
}

/// True when `path` (a file the walk of `root` returned) is an integration-test crate: a file in
/// a package's OWN `tests/` directory, `<root>/<package>/tests/...`. Such a file carries no
/// `#[cfg(test)]` marker (the whole file IS the test crate), so pruning cannot cut it and every
/// line would otherwise read as production. A `tests` directory anywhere else -- nested under
/// `src/`, or a checkout living under some `tests/` directory above `root` -- holds production
/// code and stays scanned. A path not under `root` is not a test file (it is not scanned at all).
/// Both separators are accepted on every OS: they are normalised BEFORE the prefix is stripped,
/// because on Linux a backslash is not a separator and `strip_prefix` would otherwise fail.
pub fn is_integration_test_file(root: &Path, path: &str) -> bool {
    let root = root.to_string_lossy().replace('\\', "/");
    let path = path.replace('\\', "/");
    let Ok(below_root) = Path::new(&path).strip_prefix(&root) else {
        return false;
    };
    let below_root = below_root.to_string_lossy();
    let mut parts = below_root.split('/').filter(|part| !part.is_empty());
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(_package), Some("tests"), Some(_))
    )
}

/// `path` (a file the walk of `root` returned) relative to the WORKSPACE root -- the directory
/// holding `root` -- `/`-separated; `None` when `path` is not below it. Both separators are
/// normalised first on every OS (on Linux `\` is not a separator and `parent()` would be wrong).
pub fn workspace_relative(root: &Path, path: &str) -> Option<String> {
    let root = root.to_string_lossy().replace('\\', "/");
    let workspace = Path::new(&root).parent()?;
    let path = path.replace('\\', "/");
    let below = Path::new(&path).strip_prefix(workspace).ok()?;
    let parts: Vec<String> = below
        .to_string_lossy()
        .replace('\\', "/")
        .split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect();
    Some(parts.join("/"))
}

/// True when `path` IS the file at `relative`, its full `/`-separated path from the workspace root
/// (`crates/dig-app-core/src/rewards/mint.rs`). Exact: `admint.rs` is not `mint.rs`
/// (dig_ecosystem#3478).
pub fn is_workspace_file(root: &Path, path: &str, relative: &str) -> bool {
    workspace_relative(root, path).as_deref() == Some(relative)
}

/// `Ok` when the walk of `root` reads the file at `path` (either separator) as PRODUCTION code;
/// otherwise why not: outside the walked tree, not a `.rs` file, inside build output, or an
/// integration-test file. The rules `source_escapes` applies to a `#[path]` target, which calls
/// this very function (dig_ecosystem#3479).
pub fn walk_reads_as_production(root: &Path, path: &str) -> Result<(), String> {
    let root_parts = lexical_normalize(&root.to_string_lossy());
    let target = lexical_normalize(path);
    if !(target.len() > root_parts.len() && target.starts_with(&root_parts)) {
        return Err(format!("`{path}` leaves the walked tree"));
    }
    if !is_walked_rust_file(Path::new(&target.join("/"))) {
        return Err(format!("`{path}` is not a `.rs` file"));
    }
    let root_text = root_parts.join("/");
    let in_build_output = (root_parts.len() + 1..=target.len())
        .any(|end| is_build_output_dir(Path::new(&root_text), Path::new(&target[..end].join("/"))));
    if in_build_output {
        return Err(format!("`{path}` is in build output (`target/`)"));
    }
    if is_integration_test_file(Path::new(&root_text), &target.join("/")) {
        return Err(format!("`{path}` is an integration-test file"));
    }
    Ok(())
}

/// Every way `file` (the PRODUCTION tree of the source file at `path`, `cfg(test)` already pruned,
/// scanned under `root`) pulls in code that the walk of `root` would not parse as that file's own:
/// one message per escape, empty when there is none.
///
/// A sole-caller guard walks the parsed files under `root`; `include!(..)` splices code from a
/// file nobody parsed, and a `#[path = ".."]` module can resolve outside `root`, to a non-`.rs`
/// file, into `target/` (build output) or to an integration-test file the walk skips -- each hides
/// a caller from the guard. `include_str!` / `include_bytes!` embed data, not code, so they are
/// not escapes. A `#[path]` the scan cannot resolve by reading it (not a string literal, or on a
/// module nested in another module or block, where rustc resolves it differently) FAILS CLOSED.
///
/// Macro tokens are searched too and fail closed (see [`macro_token_escapes`]), as is any `use`
/// that names `include`. Accepted limit: a DEPENDENCY's macro that expands to `include!` is not
/// visible to a lexical walk.
pub fn source_escapes(file: &File, path: &str, root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    if token_stream_includes_code(file.to_token_stream()) {
        found.push(format!(
            "{path}: `include!` splices code from a file the walk never parses"
        ));
    }
    let root = lexical_normalize(&root.to_string_lossy());
    let mut visitor = PathEscapes {
        path,
        root,
        nest: 0,
        found: Vec::new(),
    };
    visitor.visit_file(file);
    found.extend(visitor.found);
    found
}

/// True when `tokens` contain the macro call `include!` (any path to it, any nesting).
fn token_stream_includes_code(tokens: TokenStream) -> bool {
    let mut previous_is_include = false;
    for tree in tokens {
        match &tree {
            TokenTree::Group(group) if token_stream_includes_code(group.stream()) => return true,
            TokenTree::Punct(punct)
                if previous_is_include
                    && punct.as_char() == '!'
                    && punct.spacing() == Spacing::Alone =>
            {
                return true
            }
            _ => {}
        }
        previous_is_include =
            matches!(&tree, TokenTree::Ident(ident) if ident.unraw() == "include");
    }
    false
}

/// Collects every `#[path]` module attribute that escapes the walked tree.
struct PathEscapes<'a> {
    path: &'a str,
    root: Vec<String>,
    /// How many inline modules / blocks enclose the node being visited.
    nest: usize,
    found: Vec<String>,
}

impl PathEscapes<'_> {
    fn escape(&mut self, why: &str) {
        self.report(&format!("`#[path]` {why}"));
    }

    fn report(&mut self, message: &str) {
        self.found.push(format!("{}: {message}", self.path));
    }

    /// The directory of the scanned file, `/`-separated.
    fn dir(&self) -> String {
        let path = self.path.replace('\\', "/");
        path.rsplit_once('/')
            .map_or(String::new(), |(dir, _)| dir.to_owned())
    }

    fn check_target(&mut self, value: &str) {
        let value = value.replace('\\', "/");
        if value.starts_with('/') || value.contains(':') {
            return self.escape(&format!("`{value}` is an absolute path"));
        }
        // The remaining rules (under the walked root, `.rs`, not build output, not an
        // integration-test file) are the walk's own, shared so the two cannot drift.
        let root = self.root.join("/");
        if let Err(why) =
            walk_reads_as_production(Path::new(&root), &format!("{}/{value}", self.dir()))
        {
            self.escape(&why);
        }
    }
}

impl<'ast> Visit<'ast> for PathEscapes<'_> {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        if module.ident.unraw() == "target" {
            // Out of line it may resolve into `<package>/target/`, which the walk skips; inline it
            // makes a nested `mod x;` resolve under a `target/` directory. Fail closed on the name.
            self.report("a module named `target` may resolve into build output the walk skips");
        }
        for attr in &module.attrs {
            match path_attribute_value(attr) {
                PathAttr::None => {}
                PathAttr::Dynamic => self.escape("is not a string literal"),
                PathAttr::Literal(_) if self.nest > 0 || module.content.is_some() => {
                    self.escape("sits on or inside an inline module (resolved differently)");
                }
                PathAttr::Literal(value) => self.check_target(&value),
            }
        }
        let inline = module.content.is_some();
        self.nest += usize::from(inline);
        syn::visit::visit_item_mod(self, module);
        self.nest -= usize::from(inline);
    }

    fn visit_block(&mut self, block: &'ast Block) {
        self.nest += 1;
        syn::visit::visit_block(self, block);
        self.nest -= 1;
    }

    /// Every macro body or invocation (item, statement, expression, impl or trait position).
    /// Their tokens are never parsed into items, yet whatever they expand to is compiled.
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        for why in macro_token_escapes(mac.tokens.clone()) {
            self.report(why);
        }
        syn::visit::visit_macro(self, mac);
    }

    /// `use std::include as inc;` (or any path through `include`) lets any alias include code.
    fn visit_use_tree(&mut self, tree: &'ast syn::UseTree) {
        let named = match tree {
            syn::UseTree::Path(path) => &path.ident,
            syn::UseTree::Name(name) => &name.ident,
            syn::UseTree::Rename(rename) => &rename.ident,
            syn::UseTree::Glob(_) | syn::UseTree::Group(_) => {
                return syn::visit::visit_use_tree(self, tree)
            }
        };
        if named.unraw() == "include" {
            self.report("`include!` is imported under a `use`; any alias can then include code");
        }
        syn::visit::visit_use_tree(self, tree);
    }
}

/// Why the tokens of a macro body or invocation (searched recursively) are an escape, one entry
/// per suspicious sequence. A lexical scan cannot know what a macro expands to, so this FAILS
/// CLOSED on the sequences that could expand to unscanned code: a `#[path]` module attribute (its
/// declaring context cannot be resolved), the bare ident `include` (it may be passed on as a macro
/// name), and a metavariable invoked as a macro (`$i!(..)`, which may be `include`).
fn macro_token_escapes(tokens: TokenStream) -> Vec<&'static str> {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let mut why = Vec::new();
    for (at, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => {
                if at > 0 && is_hash(&trees[at - 1]) && is_path_attribute(group) {
                    why.push("`#[path]` inside a macro: its declaring context cannot be resolved lexically");
                }
                why.extend(macro_token_escapes(group.stream()));
            }
            TokenTree::Ident(ident) if ident.unraw() == "include" => {
                why.push("the ident `include` inside a macro: it may be passed as a macro name");
            }
            // The keyword, not the attribute spelling: `#[$m] mod x;` takes its `#[path]` from the
            // invocation, so no lexical rule can see what the module resolves to.
            TokenTree::Ident(ident) if ident.unraw() == "mod" => {
                why.push("a module declared inside macro tokens: its path and attributes cannot be resolved lexically");
            }
            TokenTree::Punct(punct) if punct.as_char() == '$' => {
                let invoked = matches!(trees.get(at + 1), Some(TokenTree::Ident(_)))
                    && matches!(trees.get(at + 2), Some(TokenTree::Punct(p)) if p.as_char() == '!');
                if invoked {
                    why.push(
                        "a metavariable invoked as a macro inside a macro: it may be `include`",
                    );
                }
            }
            _ => {}
        }
    }
    why
}

fn is_hash(tree: &TokenTree) -> bool {
    matches!(tree, TokenTree::Punct(punct) if punct.as_char() == '#')
}

/// `[path ..]` or `[cfg_attr(.., path = ..)]`, the bracket group after a `#`.
fn is_path_attribute(group: &proc_macro2::Group) -> bool {
    if group.delimiter() != Delimiter::Bracket {
        return false;
    }
    let mut inner = group.stream().into_iter();
    match inner.next() {
        Some(TokenTree::Ident(ident)) if ident.unraw() == "path" => true,
        Some(TokenTree::Ident(ident)) if ident.unraw() == "cfg_attr" => {
            !matches!(cfg_attr_path_value(group.stream()), PathAttr::None)
        }
        _ => false,
    }
}

/// True when `path` is the single ident `name`, however it is spelled (`r#path` is `path`).
fn is_named(path: &syn::Path, name: &str) -> bool {
    path.get_ident().is_some_and(|ident| ident.unraw() == name)
}

/// What a module attribute says about `path`.
enum PathAttr {
    /// Not a `path` attribute.
    None,
    /// `path = <not a string literal>`.
    Dynamic,
    Literal(String),
}

/// `#[path = "x"]`, or the `path = "x"` inside a `#[cfg_attr(<predicate>, ..)]`.
fn path_attribute_value(attr: &Attribute) -> PathAttr {
    match &attr.meta {
        Meta::NameValue(pair) if is_named(&pair.path, "path") => match &pair.value {
            Expr::Lit(lit) => match &lit.lit {
                Lit::Str(text) => PathAttr::Literal(text.value()),
                _ => PathAttr::Dynamic,
            },
            _ => PathAttr::Dynamic,
        },
        Meta::List(list) if is_named(&list.path, "cfg_attr") => {
            cfg_attr_path_value(list.tokens.clone())
        }
        _ => PathAttr::None,
    }
}

/// The `path = ..` inside `cfg_attr` tokens (groups searched too, so a nested `cfg_attr` counts).
fn cfg_attr_path_value(tokens: TokenStream) -> PathAttr {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (at, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => {
                let found = cfg_attr_path_value(group.stream());
                if !matches!(found, PathAttr::None) {
                    return found;
                }
            }
            TokenTree::Ident(ident) if ident.unraw() == "path" => {
                let is_assignment =
                    matches!(trees.get(at + 1), Some(TokenTree::Punct(p)) if p.as_char() == '=');
                if is_assignment {
                    return match trees.get(at + 2) {
                        Some(TokenTree::Literal(lit)) => {
                            syn::parse_str::<syn::LitStr>(&lit.to_string())
                                .map_or(PathAttr::Dynamic, |text| PathAttr::Literal(text.value()))
                        }
                        _ => PathAttr::Dynamic,
                    };
                }
            }
            _ => {}
        }
    }
    PathAttr::None
}

/// `/`-separated `path` without `.` and with `..` applied lexically (no filesystem access): a
/// `..` with nothing left to pop is kept, so a path that climbs above its start stays visible.
fn lexical_normalize(path: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    for part in path.replace('\\', "/").split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|last| last != "..") => {
                parts.pop();
            }
            other => parts.push(other.to_owned()),
        }
    }
    parts
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
/// follow, by design: a call through a bound value, `(d.begin)(x)`, and a UFCS call
/// `Type::begin(..)` -- both are name-level limits.
///
/// Renames of `module` are resolved from `file` ALONE here; a guard that scans many files must
/// instead resolve them across all of them ([`module_aliases`]) and call [`module_item_uses_in`],
/// or a rename made in one file and used from another is invisible.
pub fn module_item_uses(file: &File, module: &str, item: &str) -> ModuleItemUses {
    let names = module_aliases([file], module);
    module_item_uses_in(file, module, item, &names)
}

/// [`module_item_uses`] with the names that refer to `module` supplied by the caller -- the result
/// of [`module_aliases`] over every file the guard scans.
///
/// A path ending in `<name>::item` is counted, `name` being `module` or any of `names`.
/// `use a::module::item;`, `use a::module::*;`, a glob of a rename and a public rename are
/// escapes: the bare name they introduce cannot be told from any other. So is every OTHER way of
/// writing a path that ends in `item` -- an expression path or a `use` leaf whose previous segment
/// is neither `module` nor one of `names` (`unknown::item(x)`, `super::item(x)`): it may resolve
/// to the guarded fn through a rename this scan did not see, and an unresolvable path fails
/// CLOSED. A private rename is not itself reported.
pub fn module_item_uses_in(
    file: &File,
    module: &str,
    item: &str,
    names: &BTreeSet<String>,
) -> ModuleItemUses {
    let mut trees = UseTrees {
        module,
        item,
        names,
        escapes: Vec::new(),
    };
    trees.visit_file(file);

    let mut uses = ModuleItemUses {
        escapes: trees.escapes,
        ..ModuleItemUses::default()
    };
    for name in names {
        let path = format!("{name}::{item}");
        uses.references += count_path_references(file, &path);
        uses.calls += count_path_calls(file, &path);
    }
    for written in scan(file).paths {
        if is_unresolved_item_path(&written, item, names) {
            push_unique(&mut uses.escapes, unresolved_message(&written, module));
        }
    }
    uses
}

/// Every name that refers to `module` in `files`: `module` itself plus every `use .. as <name>`
/// rename of it, a rename of a rename, and so on until nothing new is added (a fixpoint, so the
/// order of the files and of the `use` items cannot matter). A rename counts whatever prefix its
/// source is written with -- `self::`, `super::`, `crate::`, a nested group, a `{self as x}`.
///
/// Workspace-wide on purpose: a private `use self::module as cc;` in one file is reachable as
/// `super::cc` from a child file, whose own `use` items say nothing about it.
pub fn module_aliases<'a>(
    files: impl IntoIterator<Item = &'a File>,
    module: &str,
) -> BTreeSet<String> {
    let mut edges = RenameEdges(Vec::new());
    for file in files {
        edges.visit_file(file);
    }
    let mut names = BTreeSet::from([module.to_string()]);
    loop {
        let known = names.len();
        let found: Vec<String> = edges
            .0
            .iter()
            .filter(|(source, _)| names.contains(source))
            .map(|(_, alias)| alias.clone())
            .collect();
        names.extend(found);
        if names.len() == known {
            return names;
        }
    }
}

/// A written path that ends in `item` and is not `<known name>::item`. A bare `item(..)` is not
/// one: it can only be reached by an import, and every import of `item` is reported by the `use`
/// walk.
fn is_unresolved_item_path(written: &[String], item: &str, names: &BTreeSet<String>) -> bool {
    match written {
        [.., previous, last] => last == item && !names.contains(previous),
        _ => false,
    }
}

fn unresolved_message(path: &[String], module: &str) -> String {
    format!(
        "writes `{}`, which does not run through `{module}` or a known rename of it",
        path.join("::")
    )
}

/// Pushes `message` unless it is already there: a plain `use a::b::item;` is both a `use` leaf and
/// a written path, and is one finding.
fn push_unique(escapes: &mut Vec<String>, message: String) {
    if !escapes.contains(&message) {
        escapes.push(message);
    }
}

/// Every `source -> alias` rename in the `use` items of a file, at any nesting depth.
struct RenameEdges(Vec<(String, String)>);

impl RenameEdges {
    fn tree(&mut self, tree: &UseTree, previous: Option<&str>) {
        match tree {
            UseTree::Path(path) => {
                let segment = path.ident.unraw().to_string();
                self.tree(&path.tree, Some(&segment));
            }
            UseTree::Rename(rename) => {
                let written = rename.ident.unraw().to_string();
                // `{self as x}` renames the segment before the group.
                let source = if written == "self" {
                    previous.map(str::to_string)
                } else {
                    Some(written)
                };
                if let Some(source) = source {
                    self.0.push((source, rename.rename.unraw().to_string()));
                }
            }
            UseTree::Group(group) => {
                for inner in &group.items {
                    self.tree(inner, previous);
                }
            }
            UseTree::Name(_) | UseTree::Glob(_) => {}
        }
    }
}

impl<'ast> Visit<'ast> for RenameEdges {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        self.tree(&node.tree, None);
    }
}

/// Walks every `use` item for the trees that escape a path scan, given the names that refer to
/// the module.
struct UseTrees<'a> {
    module: &'a str,
    item: &'a str,
    names: &'a BTreeSet<String>,
    escapes: Vec<String>,
}

impl UseTrees<'_> {
    /// `prefix`: the segments written before this tree. The last one being a module name means
    /// the tree sits directly inside the module.
    fn tree(&mut self, tree: &UseTree, prefix: &mut Vec<String>, public: bool) {
        let in_module = prefix.last().is_some_and(|last| self.names.contains(last));
        match tree {
            UseTree::Path(path) => {
                prefix.push(path.ident.unraw().to_string());
                self.tree(&path.tree, prefix, public);
                prefix.pop();
            }
            UseTree::Name(name) => {
                if name.ident.unraw() == self.item {
                    self.imports_item(prefix, in_module, false);
                }
            }
            UseTree::Rename(rename) => {
                let written = rename.ident.unraw().to_string();
                if written == self.item {
                    self.imports_item(prefix, in_module, true);
                } else if public && self.is_module_name(&written, in_module) {
                    self.escapes.push(format!(
                        "publicly re-exports `{}` as `{}`",
                        self.module,
                        rename.rename.unraw()
                    ));
                }
            }
            UseTree::Glob(_) => {
                if in_module {
                    self.escapes.push(format!("globs `{}::*`", self.module));
                }
            }
            UseTree::Group(group) => {
                for inner in &group.items {
                    self.tree(inner, prefix, public);
                }
            }
        }
    }

    /// Whether a renamed `use` leaf spelled `written` is the module: its name, a known rename of
    /// it, or `self` inside it.
    fn is_module_name(&self, written: &str, in_module: bool) -> bool {
        self.names.contains(written) || (in_module && written == "self")
    }

    /// A `use` leaf named `item`: an import of the guarded fn when it sits in the module, else a
    /// path that cannot be resolved.
    fn imports_item(&mut self, prefix: &[String], in_module: bool, renamed: bool) {
        if !in_module {
            let mut path = prefix.to_vec();
            path.push(self.item.to_string());
            push_unique(&mut self.escapes, unresolved_message(&path, self.module));
            return;
        }
        let how = if renamed { " under a new name" } else { "" };
        self.escapes
            .push(format!("imports `{}::{}`{how}", self.module, self.item));
    }
}

impl<'ast> Visit<'ast> for UseTrees<'_> {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        let public = !matches!(node.vis, Visibility::Inherited);
        self.tree(&node.tree, &mut Vec::new(), public);
    }
}
