//! Tests of [`super::source_scan`], the syn-based scanner the rewards guards share
//! (dig_ecosystem#3437). Kept in their own file, not in `source_scan.rs`, because that file is
//! also compiled into the `dig-app` integration test through `#[path]`, where these tests would
//! run a second time for no reason.
//!
//! Every fixture here was an input one of the hand-rolled text cutters this replaced got wrong, or
//! a shape one of their unit tests pinned.

use super::source_scan::{
    bind_references, consts, count_and_conditions, count_method_calls, count_path_calls,
    count_path_references, eval_cfg_text, fn_named, idents, if_let_blocks,
    is_integration_test_file, is_workspace_file, module_aliases, module_item_uses,
    module_item_uses_in, normalized, parse, path_calls, production, production_at, reachable,
    source_escapes, string_literals, try_workspace_rust_sources, walk_reads_as_production, Tri,
};

/// The call every sole-caller guard counts. Assembled so this file's own text never contains the
/// needle (the old text scans would read it as a second caller).
const SUBMIT: &str = concat!("create_card::sub", "mit");

fn production_idents(src: &str) -> std::collections::BTreeSet<String> {
    idents(&production(src).expect("fixture parses"))
}

fn reachable_idents(src: &str) -> std::collections::BTreeSet<String> {
    idents(&reachable(src).expect("fixture parses"))
}

fn submit_calls(src: &str) -> usize {
    count_path_calls(&production(src).expect("fixture parses"), SUBMIT)
}

// --- the four inputs the text cutters got wrong (dig_ecosystem#3437) -------------------------

/// Gap A: a block comment quoting the marker used to make the cutter delete the next real item.
#[test]
fn a_block_comment_quoting_the_marker_keeps_the_real_item() {
    let src = concat!(
        "/* Gated on #[cfg(test)] in prose, describing a sibling module. */\n",
        "pub fn real_unrelated_builder() {\n",
        "    let _ = REAL_KEY;\n",
        "    create_card::sub",
        "mit(x);\n",
        "}\n",
        "\n",
        "#[cfg(test)]\n",
        "mod tests {\n",
        "    fn t() { let _ = TEST_ONLY_KEY; }\n",
        "}\n",
    );
    let idents = production_idents(src);
    assert!(idents.contains("REAL_KEY"));
    assert!(!idents.contains("TEST_ONLY_KEY"));
    assert_eq!(submit_calls(src), 1);
}

/// Gap A2: a trailing `//` comment quoting the marker used to hide the next caller.
#[test]
fn a_trailing_comment_quoting_the_marker_keeps_the_next_caller() {
    let src = concat!(
        "pub fn a() { setup(); } // see #[cfg(test)] below\n",
        "pub fn real_second_caller() {\n",
        "    create_card::sub",
        "mit(y);\n",
        "}\n",
    );
    assert_eq!(submit_calls(src), 1);
}

/// Gap B: a raw string with an odd number of quotes and a `}` in a test module used to panic one
/// cutter and leak test text into "production" in the other.
#[test]
fn a_raw_string_with_a_brace_in_a_test_module_does_not_leak_or_panic() {
    let src = concat!(
        "#[cfg(test)]\n",
        "mod tests {\n",
        "    const S: &str = r#\"} said \"hi\"#;\n",
        "}\n",
        "\n",
        "pub fn after() {\n",
        "    let _ = AFTER_KEY;\n",
        "}\n",
    );
    let file = production(src).expect("fixture parses");
    assert!(idents(&file).contains("AFTER_KEY"));
    assert!(
        string_literals(&file)
            .iter()
            .all(|literal| !literal.contains("said")),
        "test-module text leaked into production"
    );
}

/// Gap C: a lone `"{"` in a test module used to delete everything to end of file.
#[test]
fn a_lone_brace_in_a_string_in_a_test_module_keeps_the_caller_after_it() {
    let src = concat!(
        "#[cfg(test)]\n",
        "mod tests {\n",
        "    const OPEN: &str = \"{\";\n",
        "}\n",
        "\n",
        "pub fn real_second_caller() {\n",
        "    create_card::sub",
        "mit(z);\n",
        "}\n",
    );
    assert_eq!(submit_calls(src), 1);
}

// --- cutter regressions carried over from `create_card.rs` -----------------------------------

/// Production code written AFTER a test module stays as visible as code before it.
#[test]
fn production_code_after_a_test_module_survives() {
    let src = concat!(
        "pub fn before() {}\n",
        "\n",
        "#[cfg(test)]\n",
        "mod tests {\n",
        "    fn a_test() { assert_eq!(1, 1); }\n",
        "}\n",
        "\n",
        "pub fn after() {\n",
        "    create_card::sub",
        "mit(store_id, choice);\n",
        "}\n",
    );
    assert_eq!(submit_calls(src), 1);
    let idents = production_idents(src);
    assert!(idents.contains("before"));
    assert!(!idents.contains("a_test"));
}

/// A doc comment that only QUOTES the marker must not truncate the code after it
/// (dig_ecosystem#3367 review round 2: 53654 -> 5345 surviving bytes on `copy.rs`).
#[test]
fn a_doc_comment_quoting_the_marker_does_not_truncate_what_follows() {
    let src = concat!(
        "pub const KEPT_BEFORE: &str = \"before\";\n",
        "\n",
        "/// Gated on `#[cfg(test)]`, not `pub`, because it is only read by this module's own\n",
        "/// tests below.\n",
        "pub fn after_the_mention() {\n",
        "    create_card::sub",
        "mit(store_id, choice);\n",
        "}\n",
        "\n",
        "#[cfg(test)]\n",
        "mod tests {\n",
        "    fn a_test() {}\n",
        "}\n",
    );
    assert_eq!(submit_calls(src), 1);
    let idents = production_idents(src);
    assert!(idents.contains("KEPT_BEFORE"));
    assert!(!idents.contains("a_test"));
}

/// `wire.rs` quotes `#[cfg(test)]` in its own docs; its last production fn must survive and its
/// test module must not.
#[test]
fn wire_rs_survives_its_own_doc_comments_that_quote_the_marker() {
    let file = production(include_str!("wire.rs")).expect("wire.rs parses");
    assert!(fn_named(&file, "reserve_asset_id").is_some());
    assert!(fn_named(&file, "reserve_asset_id_is_the_dig_constants_source").is_none());
}

/// `copy.rs` documents its `#[cfg(test)]` `ALL_KEYS` with prose quoting the marker; its last
/// production const must survive and `ALL_KEYS` must be cut.
#[test]
fn copy_rs_keeps_its_last_production_const_and_cuts_all_keys() {
    let idents = idents(&production(include_str!("copy.rs")).expect("copy.rs parses"));
    assert!(idents.contains("CREATE_STATUS_UNKNOWN"));
    assert!(!idents.contains("ALL_KEYS"));
}

// --- what counts as test-only -----------------------------------------------------------------

/// dig_ecosystem#3315: a plain `mod tests` is cut whatever it is called.
#[test]
fn a_plain_cfg_test_module_is_cut() {
    let src = "fn real() { let _ = REAL; }\n#[cfg(test)]\nmod tests { fn t() { let _ = ONLY_IN_TESTS; } }\n";
    let idents = production_idents(src);
    assert!(idents.contains("REAL"));
    assert!(!idents.contains("ONLY_IN_TESTS"));
}

/// dig_ecosystem#3331: `all(test, unix)` is false in every production build, so it is cut.
#[test]
fn cfg_all_test_unix_is_cut() {
    let src = "#[cfg(all(test, unix))]\nmod unix_tests { fn t() { let _ = ONLY_IN_TESTS; } }\n";
    assert!(!production_idents(src).contains("ONLY_IN_TESTS"));
}

/// `not(test)` and `all(not(test), unix)` are production code and must be kept.
#[test]
fn cfg_not_test_shapes_are_kept() {
    for predicate in ["not(test)", "all(not(test), unix)", "any(not(test), unix)"] {
        let src = format!("#[cfg({predicate})]\nfn production_builder() {{ let _ = KEPT; }}\n");
        assert!(
            production_idents(&src).contains("KEPT"),
            "{predicate} was cut"
        );
    }
}

/// The three-valued truth table of every predicate shape dig_ecosystem PR #419's review named.
#[test]
fn cfg_truth_table() {
    let cases: &[(&str, Tri)] = &[
        ("test", Tri::False),
        ("all(test, unix)", Tri::False),
        ("all(test, feature = \"x\")", Tri::False),
        ("not(test)", Tri::True),
        ("all(not(test), unix)", Tri::Unknown),
        ("any(not(test), unix)", Tri::True),
        ("any(test, unix)", Tri::Unknown),
        ("not(all(test, unix))", Tri::True),
        ("all(any(test, unix), test)", Tri::False),
        ("unix", Tri::Unknown),
        ("feature = \"x\"", Tri::Unknown),
    ];
    for (predicate, expected) in cases {
        assert_eq!(
            eval_cfg_text(predicate),
            *expected,
            "predicate {predicate:?}"
        );
    }
}

/// A predicate that does not parse is UNKNOWN (kept), never FALSE (cut).
#[test]
fn a_malformed_predicate_is_unknown() {
    for malformed in ["all(test", "not test)", "all(test))", "", "not(test, unix)"] {
        assert_ne!(
            eval_cfg_text(malformed),
            Tri::False,
            "{malformed:?} must fail safe"
        );
    }
}

/// A comma inside a quoted feature name is not a separator, so `test` inside it is not the atom.
#[test]
fn a_comma_inside_a_quoted_feature_is_not_a_separator() {
    for predicate in [
        r#"all(unix, feature = "a,test,b")"#,
        r#"all(unix, feature = ",test,")"#,
    ] {
        assert_ne!(eval_cfg_text(predicate), Tri::False, "{predicate:?}");
    }
}

/// `#[test]` fns are test code even without a `cfg`.
#[test]
fn a_test_fn_is_cut() {
    let src = "fn real() {}\n#[test]\nfn a_test() { let _ = ONLY_IN_TESTS; }\n";
    assert!(!production_idents(src).contains("ONLY_IN_TESTS"));
}

/// `#![cfg(test)]` at the top of a file makes the whole file test code.
#[test]
fn a_file_level_cfg_test_empties_the_file() {
    let src = "#![cfg(test)]\nfn helper() { let _ = ONLY_IN_TESTS; }\n";
    assert!(production_idents(src).is_empty());
}

/// A `#[cfg(test)] #[path = ".."] mod tests;` declaration is itself test-only.
#[test]
fn a_path_test_module_declaration_is_cut() {
    let src = "fn real() {}\n#[cfg(test)]\n#[path = \"x_tests.rs\"]\nmod tests;\n";
    let idents = production_idents(src);
    assert!(idents.contains("real"));
    assert!(!idents.contains("tests"));
}

/// Test-only items are found inside `impl` blocks, nested modules and fn bodies, not only at the
/// top level.
#[test]
fn test_only_items_are_cut_at_every_nesting_level() {
    let src = concat!(
        "struct S;\n",
        "impl S {\n",
        "    fn real(&self) {}\n",
        "    #[cfg(test)]\n",
        "    fn in_impl(&self) { let _ = IN_IMPL; }\n",
        "}\n",
        "mod inner {\n",
        "    #[cfg(test)]\n",
        "    const IN_MOD: u8 = 1;\n",
        "}\n",
        "fn body() {\n",
        "    #[cfg(test)]\n",
        "    fn in_block() { let _ = IN_BLOCK; }\n",
        "}\n",
    );
    let idents = production_idents(src);
    for gone in ["IN_IMPL", "IN_MOD", "IN_BLOCK"] {
        assert!(!idents.contains(gone), "{gone} survived");
    }
    assert!(idents.contains("real"));
}

// --- what counts as reachable -----------------------------------------------------------------

/// A key named only in a `use` list is imported, not referenced -- every visibility spelling.
#[test]
fn a_name_only_in_a_use_item_is_not_reachable() {
    for src in [
        "use super::copy::{ONLY_IMPORTED_KEY};",
        "pub use super::copy::{ONLY_IMPORTED_KEY};",
        "pub(crate) use super::{ONLY_IMPORTED_KEY};",
        "pub(super) use crate::rewards::{ONLY_IMPORTED_KEY};",
        "pub(in super::module) use crate::rewards::{ONLY_IMPORTED_KEY};",
        "use super::copy::{\n    // a ; in a comment\n    ONLY_IMPORTED_KEY,\n};",
    ] {
        assert!(
            !reachable_idents(src).contains("ONLY_IMPORTED_KEY"),
            "{src}"
        );
        assert!(
            production_idents(src).contains("ONLY_IMPORTED_KEY"),
            "production keeps use: {src}"
        );
    }
}

/// A key named only inside an `#[allow(dead_code)]` builder is not reachable.
#[test]
fn a_name_only_in_a_dead_code_item_is_not_reachable() {
    let src = "#[allow(dead_code)]\nfn dead_builder() { let _ = DEAD_CODE_ONLY_KEY; }\n";
    assert!(!reachable_idents(src).contains("DEAD_CODE_ONLY_KEY"));
}

/// A brace-free dead item (a `const`) must not swallow the real builder after it.
#[test]
fn a_brace_free_dead_item_does_not_swallow_the_next_builder() {
    let src = concat!(
        "#[allow(dead_code)]\n",
        "const UNUSED_CONST: u8 = 0;\n",
        "\n",
        "fn real_builder() {\n",
        "    let _ = REAL_KEY_AFTER_BRACE_FREE_ITEM;\n",
        "}\n",
    );
    let idents = reachable_idents(src);
    assert!(idents.contains("REAL_KEY_AFTER_BRACE_FREE_ITEM"));
    assert!(!idents.contains("UNUSED_CONST"));
}

/// The marker appearing only in a comment above a real builder silences nothing.
#[test]
fn a_dead_code_marker_in_a_comment_silences_nothing() {
    let src =
        "// #[allow(dead_code)]\nfn real_builder() { let _ = REAL_KEY_AFTER_COMMENT_MARKER; }\n";
    assert!(reachable_idents(src).contains("REAL_KEY_AFTER_COMMENT_MARKER"));
}

/// `allow(dead_code)` among several lints still silences the item; a different lint does not.
#[test]
fn only_dead_code_allows_silence_an_item() {
    let silenced = "#[allow(unused, dead_code)]\nfn f() { let _ = SILENCED; }\n";
    let kept = "#[allow(unused)]\nfn f() { let _ = KEPT; }\n";
    assert!(!reachable_idents(silenced).contains("SILENCED"));
    assert!(reachable_idents(kept).contains("KEPT"));
}

/// A file-level `#![allow(dead_code)]` silences a scope, not the file's contents as references.
#[test]
fn an_inner_dead_code_allow_does_not_empty_the_file() {
    let src = "#![allow(dead_code)]\nfn f() { let _ = STILL_REFERENCED; }\n";
    assert!(reachable_idents(src).contains("STILL_REFERENCED"));
}

// --- identifiers, literals and calls ------------------------------------------------------------

/// A doc comment (an attribute to syn) contributes no identifiers and no string literals.
#[test]
fn doc_comments_contribute_nothing() {
    let file = production("/// names QUOTED_KEY and \"a literal\"\nfn f() {}\n").expect("parses");
    assert!(!idents(&file).contains("QUOTED_KEY"));
    assert!(string_literals(&file).is_empty());
}

/// Escapes and raw strings are resolved; `"` inside a raw string does not end it.
#[test]
fn string_literals_resolve_escapes_and_raw_strings() {
    let file = parse("fn f() { let _ = (\"a\\\"b\", r#\"x\"y\"#, \"line\\n\"); }").expect("parses");
    assert_eq!(string_literals(&file), vec!["a\"b", "x\"y", "line\n"]);
}

/// A literal inside a macro (`format!`, `assert!`) is still a literal.
#[test]
fn string_literals_inside_macros_are_found() {
    let file =
        parse("fn f() { let _ = format!(\"hello {}\", \"inner\"); assert!(true, \"msg\"); }")
            .expect("parses");
    let literals = string_literals(&file);
    for expected in ["hello {}", "inner", "msg"] {
        assert!(
            literals.iter().any(|l| l == expected),
            "{expected:?} missing from {literals:?}"
        );
    }
}

/// A call written inside a macro body is counted, or the "no other caller" scans fail open.
#[test]
fn calls_inside_macro_bodies_are_counted() {
    let src = concat!(
        "fn f() {\n",
        "    assert!(create_card::sub",
        "mit(a).is_ok());\n",
        "    let _ = format!(\"{}\", self.begin(b));\n",
        "    matches!(x, Some(_) if create_card::sub",
        "mit(c).is_ok());\n",
        "}\n",
    );
    let file = parse(src).expect("parses");
    assert_eq!(count_path_calls(&file, SUBMIT), 2);
    assert_eq!(count_method_calls(&file, "begin"), 1);
}

/// A path call matches on trailing segments, not on a substring of the name.
#[test]
fn path_calls_match_whole_trailing_segments() {
    let src = concat!(
        "fn f() {\n",
        "    crate::rewards::create_card::sub",
        "mit(a);\n",
        "    my_create_card::sub",
        "mit(b);\n",
        "    create_card::sub",
        "mit_later(c);\n",
        "}\n",
        "pub fn submit() {}\n",
    );
    let file = parse(src).expect("parses");
    assert_eq!(count_path_calls(&file, SUBMIT), 1);
}

/// A declaration is not a call.
#[test]
fn a_fn_declaration_is_not_a_call() {
    let file = parse("trait T { fn begin(&self); }\nfn begin2() {}\nfn f(x: X) { x.begin(); }")
        .expect("parses");
    assert_eq!(count_method_calls(&file, "begin"), 1);
    assert!(path_calls(&file).iter().all(|call| call.path != ["begin"]));
}

/// A call's arguments are split on top-level commas and keep their token shape.
#[test]
fn call_arguments_keep_their_shape() {
    let file = parse("fn f() { having_displayed(&REQUIRED, other(a, b)); }").expect("parses");
    let call = path_calls(&file)
        .into_iter()
        .find(|call| call.path == ["having_displayed"])
        .expect("call found");
    assert_eq!(call.args[0], ["&", "REQUIRED"]);
    assert_eq!(call.args.len(), 2);
}

/// `normalized` ignores formatting, so a token sequence matches however the source is spaced. (The
/// sole-caller exceptions bind through `bind_references`, which matches parsed expressions with it.)
#[test]
fn normalized_ignores_formatting() {
    let file =
        parse("fn f() {\n    if !self .begin() {}\n    Feed :: app()\n        .begin( x );\n}")
            .expect("parses");
    let text = normalized(&file);
    assert!(text.contains("if!self.begin()"));
    assert!(text.contains("Feed::app().begin(x)"));
}

// --- structure ----------------------------------------------------------------------------------

/// `fn_named` finds free fns, nested fns and methods, and says nothing for a missing name.
#[test]
fn fn_named_finds_free_nested_and_method_fns() {
    let file = parse(concat!(
        "fn free() { let _ = FREE; }\n",
        "struct S;\n",
        "impl S { fn method(&self) { let _ = METHOD; } }\n",
        "fn outer() { fn nested() { let _ = NESTED; } }\n",
    ))
    .expect("parses");
    for (name, ident) in [("free", "FREE"), ("method", "METHOD"), ("nested", "NESTED")] {
        let body = fn_named(&file, name).unwrap_or_else(|| panic!("{name} not found"));
        assert!(idents(&body).contains(ident));
    }
    assert!(fn_named(&file, "missing").is_none());
}

/// `if_let_blocks` returns the then-branch of the matching `if let` only.
#[test]
fn if_let_blocks_return_the_matching_then_branch() {
    let file = parse(concat!(
        "fn f() {\n",
        "    if let Some(shown) = shown { record(store_id, shown); }\n",
        "    if let Some(other) = other { elsewhere(); }\n",
        "}\n",
    ))
    .expect("parses");
    let blocks = if_let_blocks(&file, "Some(shown)", "shown");
    assert_eq!(blocks.len(), 1);
    assert!(idents(&blocks[0]).contains("record"));
    assert!(!idents(&blocks[0]).contains("elsewhere"));
}

/// `count_and_conditions` finds `left && right` wherever the expression sits.
#[test]
fn count_and_conditions_matches_normalized_operands() {
    let file =
        parse("fn f() { let _ = Card { enabled: live  &&  shown.is_some() }; let _ = a && b; }")
            .expect("parses");
    assert_eq!(count_and_conditions(&file, "live", "shown.is_some()"), 1);
    assert_eq!(count_and_conditions(&file, "live", "other"), 0);
}

/// `consts` lists every const item, including ones inside a nested module.
#[test]
fn consts_lists_nested_module_consts() {
    let file = parse("const A: u8 = 1;\nmod m { pub const B: u8 = 2; }").expect("parses");
    let names: Vec<String> = consts(&file).iter().map(|c| c.ident.to_string()).collect();
    assert_eq!(names, ["A", "B"]);
}

// --- failure direction ---------------------------------------------------------------------------

/// Input `syn` cannot parse is an `Err`, never a panic and never an empty "clean" result.
#[test]
fn unparseable_input_is_an_error_not_a_panic() {
    for broken in [
        "fn (",
        "#[cfg(test)]\nmod tests {",
        "pub fn after() { let _ = \"unterminated; }",
    ] {
        assert!(production(broken).is_err(), "{broken:?} must be Err");
        assert!(reachable(broken).is_err(), "{broken:?} must be Err");
        assert!(parse(broken).is_err(), "{broken:?} must be Err");
    }
}

// --- gate round 1 (dig_ecosystem#3437, dig-app#430 review + security) -------------------------------

/// The sole-caller item name, assembled so this file's own text never spells the call.
const SUBMIT_FN: &str = concat!("sub", "mit");

/// F1: a turbofish between the name and the argument list hid the call.
#[test]
fn a_turbofish_path_call_is_counted() {
    let src = concat!("fn f() { create_card::sub", "mit::<D>(b); }");
    assert_eq!(submit_calls(src), 1);
}

#[test]
fn a_turbofish_method_call_is_counted() {
    let file = production("fn f() { x.begin::<T>(a); }").expect("parses");
    assert_eq!(count_method_calls(&file, "begin"), 1);
}

/// Nested `>>`, a `->` inside the generic group and a mid-path turbofish all balance correctly.
#[test]
fn turbofish_shapes_balance() {
    let file = production(concat!(
        "fn f() {\n",
        "    x.begin::<Vec<Vec<T>>>(a);\n",
        "    x.begin::<fn(u8) -> u8>(a);\n",
        "    Vec::<u8>::new();\n",
        "    create_card::sub",
        "mit::<Vec<(A, B)>>(c);\n",
        "}\n",
    ))
    .expect("parses");
    assert_eq!(count_method_calls(&file, "begin"), 2);
    assert_eq!(count_path_calls(&file, "Vec::new"), 1);
    assert_eq!(count_path_calls(&file, SUBMIT), 1);
}

/// A comparison is not a turbofish: `a < b` followed by a group must not swallow the call.
#[test]
fn a_less_than_is_not_a_turbofish() {
    let src = concat!("fn f() { if a < b { create_card::sub", "mit(x); } }");
    assert_eq!(submit_calls(src), 1);
}

/// F2: a raw identifier is the same name.
#[test]
fn a_raw_identifier_path_call_is_counted() {
    assert_eq!(
        submit_calls(&format!("fn f() {{ create_card::r#{SUBMIT_FN}(x); }}")),
        1
    );
}

#[test]
fn a_raw_identifier_method_call_is_counted() {
    let file = production("fn f() { d.r#begin(x); }").expect("parses");
    assert_eq!(count_method_calls(&file, "begin"), 1);
}

#[test]
fn a_raw_identifier_is_named_without_its_prefix() {
    let found = production_idents("fn f() { let _ = r#ONLY_RAW_KEY; }");
    assert!(found.contains("ONLY_RAW_KEY"), "{found:?}");
    assert!(!found.contains("r#ONLY_RAW_KEY"), "{found:?}");
}

/// F3: every way to reach `create_card::submit` without writing the call literally shows up as a
/// REFERENCE (or an escaping `use`), so a "sole caller" guard can refuse it.
fn submit_uses(src: &str) -> super::source_scan::ModuleItemUses {
    module_item_uses(
        &production(src).expect("fixture parses"),
        "create_card",
        SUBMIT_FN,
    )
}

#[test]
fn a_plain_call_is_one_reference_and_one_call() {
    let uses = submit_uses(&format!("fn f() {{ create_card::{SUBMIT_FN}(x); }}"));
    assert_eq!((uses.references, uses.calls), (1, 1));
    assert!(uses.escapes.is_empty());
}

#[test]
fn a_fn_pointer_is_a_reference_that_is_not_a_call() {
    for body in [
        format!("let f = create_card::{SUBMIT_FN}; f(x);"),
        format!("xs.map(create_card::{SUBMIT_FN});"),
        format!("let f: fn(A) -> B = create_card::{SUBMIT_FN}::<D>;"),
    ] {
        let uses = submit_uses(&format!("fn f() {{ {body} }}"));
        assert_eq!(uses.references, 1, "{body}");
        assert_eq!(uses.calls, 0, "{body}");
    }
}

#[test]
fn a_reference_inside_a_macro_body_is_counted() {
    let uses = submit_uses(&format!("fn f() {{ run!(create_card::{SUBMIT_FN}); }}"));
    assert_eq!((uses.references, uses.calls), (1, 0));
}

#[test]
fn importing_the_item_is_an_escape() {
    for import in [
        format!("use a::create_card::{SUBMIT_FN};"),
        format!("use a::create_card::{SUBMIT_FN} as s;"),
        format!("use a::create_card::{{other, {SUBMIT_FN}}};"),
        format!("use a::{{b, create_card::{{{SUBMIT_FN} as s}}}};"),
        format!("pub(crate) use a::create_card::{SUBMIT_FN};"),
    ] {
        let uses = submit_uses(&format!("{import}\nfn f() {{ s(x); }}"));
        assert_eq!(uses.escapes.len(), 1, "{import}: {:?}", uses.escapes);
    }
}

#[test]
fn a_glob_of_the_module_is_an_escape() {
    let uses = submit_uses(&format!(
        "use a::create_card::*;\nfn f() {{ {SUBMIT_FN}(x); }}"
    ));
    assert_eq!(uses.escapes.len(), 1, "{:?}", uses.escapes);
}

/// `use .. create_card as cc; cc::submit(x)`: the alias is resolved within the file.
#[test]
fn a_module_alias_still_counts_its_calls() {
    let uses = submit_uses(&format!(
        "use a::create_card as cc;\nfn f() {{ cc::{SUBMIT_FN}(x); }}"
    ));
    assert_eq!((uses.references, uses.calls), (1, 1));
    assert!(uses.escapes.is_empty());
}

#[test]
fn a_module_alias_in_a_fn_body_still_counts_its_calls() {
    let uses = submit_uses(&format!(
        "fn f() {{ use a::create_card as cc; cc::{SUBMIT_FN}(x); }}"
    ));
    assert_eq!((uses.references, uses.calls), (1, 1));
}

/// Gate round 2 (dig_ecosystem#3437): every route to the fn must END counted or flagged -- a
/// reference, a call or an escape. Silence is the failure.
fn reached(uses: &super::source_scan::ModuleItemUses) -> bool {
    uses.references > 0 || !uses.escapes.is_empty()
}

/// The uses of the sole-caller fn in each of `files`, aliases resolved as a workspace-wide guard
/// resolves them.
fn workspace_submit_uses(files: &[&str]) -> Vec<super::source_scan::ModuleItemUses> {
    let parsed: Vec<_> = files
        .iter()
        .map(|src| production(src).expect("fixture parses"))
        .collect();
    let names = module_aliases(&parsed, "create_card");
    parsed
        .iter()
        .map(|file| module_item_uses_in(file, "create_card", SUBMIT_FN, &names))
        .collect()
}

/// G1: a rename of a rename of the module is still the module, in a nested module, a nested block
/// and through every spelling of the second hop.
#[test]
fn a_chain_of_module_renames_is_followed() {
    let mut missed = Vec::new();
    for src in [
        format!(
            "use a::create_card as cc; mod m {{ use super::cc as dd; fn f() {{ dd::{SUBMIT_FN}(x) }} }}"
        ),
        format!("use a::create_card::{{self as cc}}; use cc as dd; fn f() {{ dd::{SUBMIT_FN}(x) }}"),
        format!(
            "fn f() {{ use a::create_card as cc; {{ use cc as dd; dd::{SUBMIT_FN}(1); }} }}"
        ),
        format!(
            "use super::create_card as a; use self::a as b; fn f() {{ b::{SUBMIT_FN}(x) }}"
        ),
        format!(
            "use super::create_card as a; use super::{{a as b}}; fn f() {{ b::{SUBMIT_FN}(x) }}"
        ),
    ] {
        if !reached(&submit_uses(&src)) {
            missed.push(src);
        }
    }
    assert!(missed.is_empty(), "uncounted and unflagged: {missed:#?}");
}

/// G2: an alias made in one file is used from another, through a `use`, a `super::` path and a
/// `crate::` path.
#[test]
fn an_alias_made_in_another_file_is_followed() {
    let mut missed = Vec::new();
    let parent = "use self::create_card as cc;";
    for child in [
        format!("use super::cc; fn f() {{ cc::{SUBMIT_FN}(x) }}"),
        format!("fn f() {{ super::cc::{SUBMIT_FN}(x) }}"),
        format!("fn f() {{ crate::rewards::cc::{SUBMIT_FN}(x) }}"),
        format!("use super::cc::*; fn f() {{ {SUBMIT_FN}(x) }}"),
    ] {
        if !reached(&workspace_submit_uses(&[parent, &child])[1]) {
            missed.push(child);
        }
    }
    assert!(missed.is_empty(), "uncounted and unflagged: {missed:#?}");
}

/// The fail-closed catch-all: a path that ends in the fn but does not run through the module or a
/// known rename of it is reported, whatever it might resolve to.
#[test]
fn an_unresolved_path_to_the_fn_is_an_escape() {
    let mut missed = Vec::new();
    for src in [
        format!("fn f() {{ unknown::{SUBMIT_FN}(x) }}"),
        format!("fn f() {{ super::{SUBMIT_FN}(x) }}"),
        format!("use a::b::{SUBMIT_FN};"),
        format!("use a::{{b, c::{{{SUBMIT_FN} as s}}}};"),
    ] {
        if submit_uses(&src).escapes.is_empty() {
            missed.push(src);
        }
    }
    assert!(missed.is_empty(), "not reported as escapes: {missed:#?}");
}

/// A private rename is not itself a defect: only a path to the fn is.
#[test]
fn a_private_rename_alone_is_not_an_escape() {
    let uses = submit_uses("use a::create_card as cc; use self::cc as dd; fn f() { cc::other(); }");
    assert!(uses.escapes.is_empty(), "{:?}", uses.escapes);
}

/// A PUBLIC rename could be called from another file under a name this file's scan cannot see.
#[test]
fn a_public_module_rename_is_an_escape() {
    for import in [
        "pub use a::create_card as cc;",
        "pub(crate) use a::create_card as cc;",
        "pub use a::create_card::{self as cc};",
    ] {
        let uses = submit_uses(import);
        assert_eq!(uses.escapes.len(), 1, "{import}: {:?}", uses.escapes);
    }
}

/// Plain module imports are the normal spelling and are not escapes.
#[test]
fn a_plain_module_import_is_not_an_escape() {
    let uses = submit_uses("use a::create_card;\nuse a::create_card::{self, other};\nfn f() {}");
    assert!(uses.escapes.is_empty(), "{:?}", uses.escapes);
}

/// A single-name reference count (`attempt_submit`): a fn-pointer binding is not a call; the
/// definition is not a reference.
#[test]
fn a_bare_name_reference_is_counted_and_its_definition_is_not() {
    let file = production(
        "pub fn attempt_submit() {}\nfn f() { let g = attempt_submit; x::attempt_submit(1); }",
    )
    .expect("parses");
    assert_eq!(count_path_references(&file, "attempt_submit"), 2);
    assert_eq!(count_path_calls(&file, "attempt_submit"), 1);
}

/// F4: a `#[cfg(test)]` on a node that is not an item is test code too.
fn no_leak(src: &str, gone: &[&str]) {
    for found in [production_idents(src), reachable_idents(src)] {
        for name in gone {
            assert!(
                !found.contains(*name),
                "{name} leaked from {src:?}: {found:?}"
            );
        }
    }
}

#[test]
fn a_cfg_test_block_statement_is_cut() {
    no_leak(
        "fn f() { #[cfg(test)] { let _ = copy::ONLY_TEST_KEY; } real(); }",
        &["ONLY_TEST_KEY"],
    );
    assert!(production_idents("fn f() { #[cfg(test)] { x(); } real(); }").contains("real"));
}

#[test]
fn a_cfg_test_expression_statement_is_cut() {
    no_leak(
        "fn f() { #[cfg(test)] touch(TEST_ONLY_A); }",
        &["TEST_ONLY_A"],
    );
    no_leak(
        "fn f() { #[cfg(test)] if c { TEST_ONLY_B; } }",
        &["TEST_ONLY_B"],
    );
}

#[test]
fn a_cfg_test_match_arm_is_cut() {
    no_leak(
        "fn f() { match y { #[cfg(test)] A => copy::ARM_KEY, _ => 0 }; }",
        &["ARM_KEY"],
    );
}

#[test]
fn a_cfg_test_struct_field_is_cut() {
    no_leak(
        "struct S { #[cfg(test)] k: FIELD_KEY, real: u8 }",
        &["FIELD_KEY"],
    );
    no_leak("struct T(#[cfg(test)] TUPLE_KEY, u8);", &["TUPLE_KEY"]);
}

#[test]
fn a_cfg_test_enum_variant_is_cut() {
    no_leak(
        "enum E { #[cfg(test)] V(VARIANT_KEY), Real { #[cfg(test)] f: INNER_KEY } }",
        &["VARIANT_KEY", "INNER_KEY"],
    );
}

#[test]
fn a_cfg_test_struct_literal_field_is_cut() {
    no_leak(
        "fn f() { S { #[cfg(test)] a: LITERAL_KEY, b: 1 }; }",
        &["LITERAL_KEY"],
    );
}

/// The review's own input, verbatim: none of the three may leak.
#[test]
fn the_reviews_cfg_test_input_leaks_nothing() {
    no_leak(
        "fn f(){ #[cfg(test)] { let _ = copy::ONLY_TEST_KEY; } match y { #[cfg(test)] A => copy::ARM_KEY, _ => 0 }; } struct S { #[cfg(test)] k: FIELD_KEY }",
        &["ONLY_TEST_KEY", "ARM_KEY", "FIELD_KEY"],
    );
}

/// An unknown predicate keeps the node, exactly as it keeps an item.
#[test]
fn a_non_test_cfg_on_a_non_item_node_is_kept() {
    let found = production_idents(
        "fn f() { #[cfg(unix)] { KEPT_STMT; } match y { #[cfg(not(test))] A => KEPT_ARM, _ => 0 }; }",
    );
    assert!(
        found.contains("KEPT_STMT") && found.contains("KEPT_ARM"),
        "{found:?}"
    );
}

/// F5a: a walk that cannot read something fails, naming it.
#[test]
fn a_missing_walk_root_is_an_error_naming_it() {
    let root = std::env::temp_dir().join("source_scan_walk_no_such_dir_3437");
    let err = try_workspace_rust_sources(&root).expect_err("a missing root must fail");
    assert!(err.contains("source_scan_walk_no_such_dir_3437"), "{err}");
}

#[test]
fn an_unreadable_rust_file_is_an_error_naming_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    for n in 0..25 {
        std::fs::write(dir.path().join(format!("ok{n}.rs")), "fn f() {}").expect("write");
    }
    std::fs::write(dir.path().join("bad_utf8.rs"), [0xff, 0xfe, 0xfd]).expect("write");
    let err = try_workspace_rust_sources(dir.path()).expect_err("an unreadable file must fail");
    assert!(err.contains("bad_utf8.rs"), "{err}");
}

#[test]
fn a_walk_that_sees_twenty_files_or_fewer_is_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    for n in 0..20 {
        std::fs::write(dir.path().join(format!("f{n}.rs")), "fn f() {}").expect("write");
    }
    let err = try_workspace_rust_sources(dir.path()).expect_err("20 files is under the floor");
    assert!(err.contains("20"), "{err}");
}

#[test]
fn the_real_workspace_walk_sees_more_than_twenty_files() {
    let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/");
    let files = try_workspace_rust_sources(crates_dir).expect("the workspace walk succeeds");
    assert!(files.len() > 20, "{}", files.len());
}

/// F5b: `/tests/` is looked for in the path BELOW the workspace root, not in the checkout's own
/// location.
#[test]
fn a_checkout_under_a_tests_directory_does_not_hide_production_files() {
    let root = std::path::Path::new("/home/tests/ws/crates");
    assert!(!is_integration_test_file(
        root,
        "/home/tests/ws/crates/dig-app/src/bin/dig-app.rs"
    ));
    assert!(is_integration_test_file(
        root,
        "/home/tests/ws/crates/dig-app/tests/x.rs"
    ));
}

/// dig_ecosystem#3472: only a package's OWN `tests/` directory (`<root>/<package>/tests/..`) is an
/// integration test. A `tests` directory nested deeper under `src/` holds production modules and
/// must still be scanned, whichever separator the walk produced.
#[test]
fn only_a_packages_own_tests_directory_is_an_integration_test() {
    let root = std::path::Path::new("crates");
    assert!(!is_integration_test_file(
        root,
        "crates/pkg/src/a/tests/x.rs"
    ));
    assert!(!is_integration_test_file(
        root,
        r"crates\pkg\src\a\tests\x.rs"
    ));
    assert!(is_integration_test_file(root, r"crates\pkg\tests\x.rs"));
    assert!(is_integration_test_file(root, "crates/pkg/tests/x.rs"));
    assert!(is_integration_test_file(root, "crates/pkg/tests/sub/x.rs"));
    assert!(!is_integration_test_file(root, "crates/tests/src/lib.rs"));
    assert!(!is_integration_test_file(root, "crates/pkg/src/tests.rs"));
}

// --- dig_ecosystem#3462: name-level gaps left after #3437 -----------------------------------

/// Gap 1: a UFCS or fn-pointer `begin` is a reference even though it is not a method call. The
/// guard in `create_card.rs` counts references, so none of these may slip past it.
#[test]
fn a_ufcs_or_fn_pointer_begin_counts_as_a_reference() {
    let src = "trait Door { fn begin(self, x: u8); }\nfn f<D: Door + Copy>(d: D) {\n    <D as Door>::begin(d, 1);\n    Door::begin(d, 2);\n    D::begin(d, 3);\n    d.begin(4);\n    let g = D::begin;\n    let _ = [d].into_iter().map(D::begin);\n}\n";
    let file = production(src).expect("fixture parses");
    assert_eq!(
        count_path_references(&file, "begin"),
        6,
        "#3462 gap 1: every written `begin` (UFCS, fn pointer, method call) must be a reference"
    );
    assert_eq!(
        count_method_calls(&file, "begin"),
        1,
        "#3462 gap 1: count_method_calls alone sees only the `.begin(` call, which is why the guard must not use it"
    );
}

/// Gap 2 (items): `#[cfg(test)]` on a fn parameter, a generic parameter or a foreign item.
#[test]
fn a_cfg_test_fn_param_is_not_production() {
    let src = "fn f(a: u8, #[cfg(test)] b: FN_PARAM_ONLY) {}\nfn g<#[cfg(test)] GENERIC_ONLY>() {}\nextern \"C\" { #[cfg(test)] fn FOREIGN_ONLY(); }\n";
    let ids = production_idents(src);
    let leaked: Vec<&str> = ["FN_PARAM_ONLY", "GENERIC_ONLY", "FOREIGN_ONLY"]
        .into_iter()
        .filter(|name| ids.contains(*name))
        .collect();
    assert!(
        leaked.is_empty(),
        "#3462 gap 2: test-only names read as production: {leaked:?}"
    );
}

/// Gap 2 (expressions): `#[cfg(test)]` on a call or method argument, an array or tuple element,
/// or a closure parameter.
#[test]
fn a_cfg_test_call_argument_is_not_production() {
    let src = "fn h() { k(1, #[cfg(test)] CALL_ARG_ONLY); let _ = [1, #[cfg(test)] ARRAY_ONLY]; let _ = (1, #[cfg(test)] TUPLE_ONLY); let c = |#[cfg(test)] CLOSURE_ONLY: u8| 0; x.m(#[cfg(test)] METHOD_ARG_ONLY); }\n";
    let ids = production_idents(src);
    let leaked: Vec<&str> = [
        "CALL_ARG_ONLY",
        "ARRAY_ONLY",
        "TUPLE_ONLY",
        "CLOSURE_ONLY",
        "METHOD_ARG_ONLY",
    ]
    .into_iter()
    .filter(|name| ids.contains(*name))
    .collect();
    assert!(
        leaked.is_empty(),
        "#3462 gap 2: test-only names read as production: {leaked:?}"
    );
}

/// Known limits, asserting the DESIRED behaviour: macro bodies are raw tokens, so both need macro
/// expansion to fix. Run with `--ignored` to see them fail.
#[test]
#[ignore = "known limitation (dig_ecosystem#3462): macro bodies are raw tokens; needs macro expansion"]
fn macro_bodies_are_scanned_per_invocation_and_honour_cfg_test() {
    let src = "macro_rules! m { () => { d.begin(1) }; }\nfn f() { m!(); m!(); }\n";
    let n = count_method_calls(&production(src).expect("fixture parses"), "begin");
    assert_eq!(n, 2, "#3462 gap 3: two invocations, counted {n}");

    let src = "m! { #[cfg(test)] fn MACRO_ITEM_ONLY() {} }\n";
    assert!(
        !production_idents(src).contains("MACRO_ITEM_ONLY"),
        "#3462 gap 2 (macro body): a cfg(test) item inside a macro body read as production"
    );
}

// --- #3466: sole-caller exceptions bind to parsed expressions -----------------------------------

/// A string literal holding the exception shape binds nothing.
#[test]
fn bind_references_refuses_an_exception_held_only_in_a_string_literal() {
    let file = production_at("x.rs", "fn f() { let _ = \"x.begin(y)\"; }");
    assert!(bind_references(&file, "begin", &["x.begin(y)"]).is_err());
}

/// A doc comment holding the exception shape binds nothing.
#[test]
fn bind_references_refuses_an_exception_held_only_in_a_doc_comment() {
    let file = production_at(
        "x.rs",
        "/// x.begin(y)
fn f() {}",
    );
    assert!(bind_references(&file, "begin", &["x.begin(y)"]).is_err());
}

/// The excused call swapped for another reference, with a literal keeping its text, is refused (#3466 acceptance).
#[test]
fn bind_references_refuses_a_swapped_call_behind_a_literal() {
    let file = production_at(
        "x.rs",
        "fn f() { let _ = \"x.begin(y)\"; let g = <S as D>::begin; g(y); }",
    );
    assert!(bind_references(&file, "begin", &["x.begin(y)"]).is_err());
}

/// The real call binds its exception.
#[test]
fn bind_references_accepts_the_real_call() {
    let file = production_at("x.rs", "fn f() { x.begin(y); }");
    assert_eq!(bind_references(&file, "begin", &["x.begin(y)"]), Ok(()));
}

/// A reference beyond the bound exception is refused.
#[test]
fn bind_references_refuses_an_unexcused_extra_reference() {
    let file = production_at("x.rs", "fn f() { x.begin(y); let g = D::begin; }");
    assert!(bind_references(&file, "begin", &["x.begin(y)"]).is_err());
}

/// Two nested shapes cannot both be satisfied by one reference.
#[test]
fn bind_references_binds_one_reference_per_exception_when_shapes_nest() {
    let file = production_at("x.rs", "fn f() { drop(x.begin(y)); let g = D::begin; }");
    assert!(bind_references(&file, "begin", &["drop(x.begin(y))", "x.begin(y)"]).is_err());
}

/// A shape may be an expression inside a larger one (`if !self.begin()`).
#[test]
fn bind_references_binds_an_inner_expression() {
    let file = production_at("x.rs", "fn f() { if !self.begin() {} }");
    assert_eq!(bind_references(&file, "begin", &["self.begin()"]), Ok(()));
}

/// Syn leaves macro bodies as tokens, so a reference there is counted but never bound.
#[test]
fn bind_references_cannot_excuse_a_reference_in_a_macro_body() {
    let file = production_at("x.rs", "fn f() { println!(\"{:?}\", x.begin(y)); }");
    assert!(bind_references(&file, "begin", &["x.begin(y)"]).is_err());
}

/// A shape listed twice is bound by two expressions.
#[test]
fn bind_references_binds_duplicate_entries_once_each() {
    let file = production_at("x.rs", "fn f() { if !self.begin() {} if !self.begin() {} }");
    assert_eq!(
        bind_references(&file, "begin", &["!self.begin()"; 2]),
        Ok(())
    );
}

/// A shape listed twice but matched once is a stale exemption.
#[test]
fn bind_references_refuses_a_duplicate_entry_with_one_call() {
    let file = production_at("x.rs", "fn f() { if !self.begin() {} let g = D::begin; }");
    assert!(bind_references(&file, "begin", &["!self.begin()"; 2]).is_err());
}

/// `if !self.begin()` is half a statement, not an expression.
#[test]
fn bind_references_rejects_a_shape_that_is_not_an_expression() {
    let err = bind_references(
        &production_at("x.rs", "fn f() { if !self.begin() {} }"),
        "begin",
        &["if !self.begin()"],
    )
    .expect_err("a statement fragment is not an exception");
    assert!(err.contains("not a Rust expression"), "{err}");
}

/// An exception excuses exactly one reference.
#[test]
fn bind_references_rejects_a_shape_naming_the_path_twice() {
    let file = production_at("x.rs", "fn f() { a.begin(b.begin()); }");
    assert!(bind_references(&file, "begin", &["a.begin(b.begin())"]).is_err());
}

/// No exceptions means no reference may remain.
#[test]
fn bind_references_with_no_exceptions_refuses_any_reference() {
    let file = production_at("x.rs", "fn f() { x.begin(y); }");
    assert!(bind_references(&file, "begin", &[]).is_err());
}

/// A call inside `#[cfg(test)]` code is not production.
#[test]
fn bind_references_ignores_pruned_test_code() {
    let file = production_at(
        "x.rs",
        "fn f() {} #[cfg(test)] mod t { fn g() { x.begin(y); } }",
    );
    assert_eq!(bind_references(&file, "begin", &[]), Ok(()));
}

// --- dig_ecosystem#3473: code the sole-caller walk cannot see ------------------------------

/// Escapes `src` (as the file at `path`, scanned under `crates`) holds in its production tree.
fn escapes_of(path: &str, src: &str) -> Vec<String> {
    source_escapes(
        &production_at(path, src),
        path,
        std::path::Path::new("crates"),
    )
}

/// `include!` splices code the walk never parses, however it is spelled or nested.
#[test]
fn an_include_macro_is_an_escape() {
    for src in [
        r#"fn f(){ include!("x.txt"); }"#,
        r#"fn f(){ std::include!("y.rs"); }"#,
        r#"fn f(){ let v = vec![include!("x.txt")]; }"#,
        r#"include!("x.txt");"#,
    ] {
        assert!(!escapes_of("crates/p/src/a.rs", src).is_empty(), "{src}");
    }
}

/// `include_str!` / `include_bytes!` embed data, not code: nothing to walk.
#[test]
fn include_str_and_include_bytes_are_data_not_escapes() {
    let src = r#"fn f(){ let _ = include_str!("x.txt"); let _ = include_bytes!("y.png"); }"#;
    assert!(escapes_of("crates/p/src/a.rs", src).is_empty());
}

/// A `#[path]` that leaves the scanned tree, names a non-`.rs` file, a build output, an
/// integration-test file, sits in an inline module, or is not a literal, hides code from the walk.
#[test]
fn a_path_attribute_that_leaves_the_walked_production_tree_is_an_escape() {
    for src in [
        r#"#[path = "../../../outside/x.rs"] mod m;"#,
        r#"#[path = "x.txt"] mod m;"#,
        r#"#[path = "../target/x.rs"] mod m;"#,
        r#"#[path = "../tests/x.rs"] mod m;"#,
        r#"#[cfg_attr(unix, path = "../../../o.rs")] mod m;"#,
        r#"mod outer { #[path = "b.rs"] mod m; }"#,
        r#"#[path = concat!("a", ".rs")] mod m;"#,
    ] {
        assert!(!escapes_of("crates/p/src/a.rs", src).is_empty(), "{src}");
    }
    // A backslash path is judged the same on every OS.
    assert!(!escapes_of(
        r"crates\p\src\a.rs",
        r#"#[path = "..\\..\\..\\o.rs"] mod m;"#
    )
    .is_empty());
}

/// Test-only code is pruned before the scan; a `#[path]` that stays inside the tree is fine,
/// and a package's `build.rs` resolves its `#[path]` against the package directory.
#[test]
fn test_only_code_and_in_tree_paths_are_not_escapes() {
    for (path, src) in [
        (
            "crates/p/src/a.rs",
            r#"#[cfg(test)] mod t { include!("x.txt"); }"#,
        ),
        (
            "crates/p/src/a.rs",
            r#"#[cfg(test)] #[path = "../../../o.txt"] mod t;"#,
        ),
        (
            "crates/dig-app/build.rs",
            r#"#[path = "build/res.rs"] mod res;"#,
        ),
        (
            "crates/diga/build.rs",
            r#"#[path = "../dig-app/build/res.rs"] mod res;"#,
        ),
    ] {
        assert!(escapes_of(path, src).is_empty(), "{path}: {src}");
    }
}

// --- dig_ecosystem#3473, security finding 1: `#[path]` hidden in macro tokens -------------------

/// A `#[path]` inside macro tokens is never a parsed `ItemMod`, yet the module it declares is
/// compiled: the scan cannot resolve its declaring context, so it FAILS CLOSED.
#[test]
fn a_path_attribute_inside_macro_tokens_is_an_escape() {
    for src in [
        r#"macro_rules! m { () => { #[path = "/abs/evil.rs"] mod x; } } m!();"#,
        r#"id! { #[path = "../../../evil.rs"] mod x; }"#,
        r#"fn f(){ m!{ #[cfg_attr(unix, path = "a.rs")] mod x; } }"#,
    ] {
        assert!(!escapes_of("crates/p/src/a.rs", src).is_empty(), "{src}");
    }
}

// --- security round 2, finding 1: any `mod` inside macro tokens ----------------------------------

/// The `mod` KEYWORD inside macro tokens is an escape: `#[$m] mod x;` takes its `#[path]` from the
/// invocation, and a lexical walk cannot know what a macro emits.
#[test]
fn a_module_declared_in_macro_tokens_is_an_escape() {
    for src in [
        r#"macro_rules! m { ($m:meta) => { #[$m] mod x; } } m!(path="/abs/evil.rs");"#,
        "macro_rules! m { ($($t:tt)*) => { #[$($t)*] mod x; } }",
        "macro_rules! m { () => { mod x; } }",
        "fn f(){ m!{ mod y {} } }",
    ] {
        assert!(!escapes_of("crates/p/src/a.rs", src).is_empty(), "{src}");
    }
}

// --- security round 2, finding 2: raw idents and nested `cfg_attr` ------------------------------

/// `r#path` is `path`; a `cfg_attr` nested in a `cfg_attr` still carries the path.
#[test]
fn a_raw_ident_path_attribute_and_nested_cfg_attr_are_escapes() {
    for src in [
        r#"#[r#path = "../../../evil.rs"] mod x;"#,
        r#"#[cfg_attr(a, cfg_attr(b, path = "../../../o.rs"))] mod m;"#,
        r#"#[r#cfg_attr(a, r#path = "../../../o.rs")] mod m;"#,
        r#"id! { #[r#path = "../../../evil.rs"] mod x; }"#,
    ] {
        assert!(!escapes_of("crates/p/src/a.rs", src).is_empty(), "{src}");
    }
}

// --- security round 2, finding 3: a module named `target` ---------------------------------------

/// A module named `target` (raw or not, inline or out of line) can resolve into build output.
#[test]
fn any_module_named_target_is_an_escape() {
    for src in ["mod r#target;", "mod target { mod x; }", "mod target {}"] {
        assert!(!escapes_of("crates/p/src/a.rs", src).is_empty(), "{src}");
    }
}

/// Lookalikes that must stay quiet: a string literal in a macro is not the keyword.
#[test]
fn keyword_lookalikes_in_macros_are_not_escapes() {
    for src in [
        r#"fn f(){ println!("mod target"); }"#,
        "fn f(){ vec![1, 2]; }",
        "macro_rules! m { ($e:expr) => { $e } }",
    ] {
        assert!(escapes_of("crates/p/src/a.rs", src).is_empty(), "{src}");
    }
}

// --- security finding 2: `include!` reached under another name ----------------------------------

/// `include!` imported or passed under another name still splices unparsed code.
#[test]
fn an_include_macro_reached_under_another_name_is_an_escape() {
    for src in [
        r#"use std::include as inc; fn f(){ inc!("x.rs"); }"#,
        r#"macro_rules! m { ($i:ident) => { $i!("x.rs") } } m!(include);"#,
        "use std::include;",
        "macro_rules! m { ($i:ident) => { $i!() } }",
    ] {
        assert!(!escapes_of("crates/p/src/a.rs", src).is_empty(), "{src}");
    }
}

/// Data includes, an `expr` fragment and a field named `include` are not escapes.
#[test]
fn include_lookalikes_are_not_escapes() {
    for src in [
        r#"fn f(){ let _ = include_str!("x.txt"); }"#,
        "macro_rules! m { ($e:expr) => { $e } }",
        "struct S { include: bool }",
    ] {
        assert!(escapes_of("crates/p/src/a.rs", src).is_empty(), "{src}");
    }
}
// --- security finding 3: a `target` directory below a package's `src` ---------------------------

/// `mod target;` from a package source resolves into `src/target/`, which is walked like any
/// other directory, and from `build.rs` into the skipped `<pkg>/target/`: fail closed.
#[test]
fn an_out_of_line_target_module_is_an_escape() {
    assert!(!escapes_of("crates/p/src/a.rs", "mod target;").is_empty());
}

/// Only Cargo's output directories are skipped, so a `#[path]` into a deeper `target` directory
/// resolves to scanned code; one climbing into `<pkg>/target` still escapes.
#[test]
fn a_path_into_a_nested_target_directory_is_walked_not_an_escape() {
    assert!(escapes_of("crates/p/src/a.rs", r#"#[path = "target/x.rs"] mod m;"#).is_empty());
    assert!(!escapes_of("crates/p/src/a.rs", r#"#[path = "../target/x.rs"] mod m;"#).is_empty());
}

/// Only Cargo's own output directories are skipped by the walk; a `target` directory deeper
/// (inside a package's `src`) is source and is scanned.
#[test]
fn only_cargos_output_directories_are_skipped_by_the_walk() {
    use super::source_scan::is_build_output_dir;
    let root = std::path::Path::new("crates");
    for (dir, skipped) in [
        ("crates/pkg/src/target", false),
        (r"crates\pkg\src\target", false),
        ("crates/pkg/target", true),
        (r"crates\pkg\target", true),
        // `<root>/target` is a package named `target`: walked. Its own `target/` is skipped.
        ("crates/target", false),
        ("crates/target/target", true),
        ("crates/pkg/src", false),
    ] {
        assert_eq!(
            is_build_output_dir(root, std::path::Path::new(dir)),
            skipped,
            "{dir}"
        );
    }
}

/// dig_ecosystem#3478: an exemption names a FILE by its full path from the workspace root, so a
/// file that merely ENDS with the exempt file's name is not exempt.
#[test]
fn an_exempt_file_is_matched_by_its_full_path_not_its_name() {
    use std::path::Path;
    const MINT: &str = "crates/dig-app-core/src/rewards/mint.rs";
    let root = Path::new("/w/crates");
    for (path, relative) in [
        ("/w/crates/x/src/admint.rs", MINT),
        (
            "/w/crates/x/src/foo_create_card.rs",
            "crates/dig-app-core/src/rewards/create_card.rs",
        ),
        (
            "/w/crates/x/src/recreate_card.rs",
            "crates/dig-app-core/src/rewards/create_card.rs",
        ),
        ("/w/crates/dig-app-core/src/rewards/sub/mint.rs", MINT),
        ("/w/crates/dig-app-core/src/account/profile_mint.rs", MINT),
        ("/elsewhere/crates/dig-app-core/src/rewards/mint.rs", MINT),
    ] {
        assert!(!is_workspace_file(root, path, relative), "{path}");
    }
    assert!(is_workspace_file(
        root,
        "/w/crates/dig-app-core/src/rewards/mint.rs",
        MINT
    ));
    assert!(is_workspace_file(
        Path::new(r"C:\w\crates"),
        r"C:\w\crates\dig-app-core\src\rewards\mint.rs",
        MINT
    ));
    assert!(is_workspace_file(
        Path::new("C:/w/crates"),
        r"C:\w\crates\dig-app-core\src\rewards\create_card.rs",
        "crates/dig-app-core/src/rewards/create_card.rs"
    ));
}

/// dig_ecosystem#3479: the walk's three "is this production?" rules are ONE function shared with
/// `source_escapes`, so a manifest-declared target and a `#[path]` target cannot disagree.
#[test]
fn walk_reads_as_production_agrees_with_source_escapes() {
    use std::path::Path;
    for (target, escapes) in [
        ("../../../outside/x.rs", true),
        ("../target/x.rs", true),
        ("../tests/x.rs", true),
        ("b.rs", false),
        ("b.txt", true),
        ("../../q/tests/x.rs", true),
        ("../../q/src/tests/x.rs", false),
        ("../../q/target/x.rs", true),
        ("../../target/x.rs", false),
        ("src/.rs", true),
        ("sub/.rs", true),
        ("x/.rs", true),
        ("src/a.rs", false),
    ] {
        let src = format!("#[path = \"{target}\"] mod m;");
        let found = !source_escapes(
            &production(&src).expect("fixture parses"),
            "crates/p/src/a.rs",
            Path::new("crates"),
        )
        .is_empty();
        let unread =
            walk_reads_as_production(Path::new("crates"), &format!("crates/p/src/{target}"))
                .is_err();
        assert_eq!(found, escapes, "source_escapes disagrees on {target}");
        assert_eq!(
            unread, found,
            "the helper disagrees with source_escapes on {target}"
        );
    }
}
