//! The honest copy must reach the surfaces that can actually PRODUCE an unusable account folder.
//!
//! # The defect this exists to catch, which really shipped
//!
//! `UnlockFailure::Unusable` was added for the tray's `Unlock` action — and `Unlock` **cannot produce
//! it**. `KeystoreError::UnsafeRoot` and `InsecurePermissions` are raised by the keystore backend's
//! WRITE; the unlock path only reads. The flows that do write — create, restore, and the replacement
//! enrolments — each called an `Option`-returning wrapper that discarded the verdict, so every one of
//! them answered an unusable folder with an invitation to try again. The new verdict was correct, the
//! new words were correct, and the pair was wired to the one path where the condition never occurs.
//!
//! # Why this is a source-text test
//!
//! The routing lives in `bin/dig-app.rs`, which is a binary with `#[cfg(feature = "tray")]` paths that
//! draw native windows: no test can call them, and a library-side assertion on
//! [`dig_app_core::account::boot::failure_notice`] proves only that the right words EXIST. What has to
//! be held is that the binary asks for them instead of writing its own — so that is asserted where it
//! is decidable, in the source.
//!
//! It is honest about being narrow: it cannot see copy assembled at runtime, and it would not notice
//! the same mistake in a different file. What it catches is the cheap-to-reintroduce regression —
//! putting a retry invitation back at a call site that cannot honour it.
//!
//! The BEHAVIOUR of the shell's own verdict routing is asserted separately and for real, against the
//! production `ShellCustodian`, in `bin/dig-app.rs`'s `shell_custodian_verdict_tests`.

/// The tray binary's CODE, with every comment line dropped.
///
/// Stripping comments is required for correctness, not tidiness: the routing is DOCUMENTED at each
/// call site by quoting the misleading sentence it replaced, so a naive search over the whole file
/// matches the explanation of the defect and fails on a correct file.
fn tray_code() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/dig-app.rs");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the tray binary is readable at {}: {e}", path.display()));
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every account-establishing failure is answered by words the LIBRARY chose from the verdict.
///
/// The two literals asserted absent are the exact sentences that shipped: they are what an unusable
/// account folder used to be answered with, and reverting either call site to `open_account` brings the
/// literal back here rather than merely changing an enum.
#[test]
fn the_create_and_restore_paths_choose_their_words_from_the_verdict() {
    let code = tray_code();

    for flow in ["AccountAction::Create", "AccountAction::Restore"] {
        assert!(
            code.contains(&format!("failure_notice({flow}")),
            "the {flow} path must ask the library for its words, so the choice is testable"
        );
    }

    for retry in [
        "You can start again from the DIG tray menu",
        "you can try again from the DIG menu whenever you are ready",
    ] {
        assert!(
            !code.contains(retry),
            "a retry invitation is hardcoded at a call site again: {retry:?} — it must come from \
             `failure_notice`, which withholds it when the folder cannot hold an account"
        );
    }

    assert!(
        !code.contains("open_account(&"),
        "a writing flow is back on the verdict-discarding wrapper"
    );
}

/// Every enrolling `AccountCustodian` method THREADS its verdict — and the list is derived from the
/// trait, not written here.
///
/// # Why a hand-written list could not hold this (the re-gate F1 defect)
///
/// The assertion this replaces enumerated the writing flows in prose — *"create, import, restore,
/// replace-from-phrase"* — and **replace-with-NEW was simply absent**. That is the one arm that had
/// shipped with its verdict discarded: `ShellCustodian::enrol_new` answered every unsuccessful setup
/// with a synthesised `Err(UnlockFailure::Refused)`, so `journey`'s honest post-removal window was dead
/// code in production. A hand-enumerated flow list cannot fail for a flow nobody thought of, which is
/// precisely the failure mode it was there to prevent.
///
/// So the list is READ OFF the `AccountCustodian` trait: every method whose signature answers
/// `Result<(), UnlockFailure>` OR `Result<(), EnrolFailure>` is a flow that must report a verdict, and
/// no such method's body in the shell may NAME a verdict — the value has to arrive from the enrolment.
/// Adding a fifth custodian arm puts it under this assertion the moment the trait declares it.
///
/// `EnrolFailure` (dig-app#235/#342) is itself a verdict-THREADING type, not a synthesized one: both
/// its variants carry the real `UnlockFailure` the enrolment or the re-open reported, tagged only with
/// WHICH step produced it. Constructing `EnrolFailure::NotEnrolled(verdict)` from a threaded `verdict`
/// is correct and expected here; [`named_verdicts`] still catches the actual regression — a literal
/// `UnlockFailure::<Variant>` spelled inside that construction instead of the threaded identifier.
#[test]
fn every_enrolling_custodian_arm_threads_its_verdict() {
    let arms = enrolling_custodian_methods();
    // A vacuity FLOOR, not the enumeration: the arms below are the two the trait declares today, so a
    // parse that silently stopped finding them would make every assertion after this point pass over
    // nothing. The enumeration itself is whatever `enrolling_custodian_methods` returns, which is how a
    // future third arm gets covered without anyone editing this list.
    for known in ["enrol_new", "enrol_from"] {
        assert!(
            arms.iter().any(|arm| arm == known),
            "the derivation stopped seeing `{known}`, so this test now measures nothing; parsed {arms:?}"
        );
    }

    let code = tray_code();
    for arm in &arms {
        let body = shell_method_body(&code, arm);
        let named = named_verdicts(&body);
        assert!(
            named.is_empty(),
            "`{arm}` names {named:?} itself instead of threading the verdict the enrolment reported; \
             that is what made the honest unusable-folder window unreachable in production:\n{body}"
        );
    }
}

/// The enrolling arms of `AccountCustodian`, read off the trait declaration in `dig-app-core`.
///
/// "Enrolling" is decided by the SIGNATURE — a method that answers `Result<(), UnlockFailure>` or
/// `Result<(), EnrolFailure>` is one that reports a verdict — so a new arm is picked up from the type
/// rather than from a reader noticing.
fn enrolling_custodian_methods() -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../dig-app-core/src/account/journey.rs");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the journey module is readable at {}: {e}", path.display()));
    enrolling_custodian_methods_from(&source)
}

/// [`enrolling_custodian_methods`], over an injected source string — the pure form a unit test can
/// drive against a crafted trait declaration instead of the real file (dig-app#358).
///
/// # Two parse evasions this closes
///
/// The prior implementation matched each trait item on a SINGLE LINE, which two shapes evade —
/// neither hypothetical: the trait's own arms sit at ~78 columns today and rustfmt wraps past 100.
///
/// 1. **A rustfmt-wrapped signature.** `fn enrol_new(&self)\n    -> Result<(), UnlockFailure>;` splits
///    the return type onto its own line, so a per-line scan never sees `"fn "` and
///    `"Result<(), UnlockFailure>"` together. Fixed by parsing on trait-ITEM boundaries (each
///    body-less trait method ends in exactly one `;`, which a line wrap cannot move) and normalizing
///    internal whitespace before matching, rather than scanning line by line.
/// 2. **A type-aliased return.** `fn enrol_new(&self) -> EnrolResult;` where
///    `type EnrolResult = Result<(), UnlockFailure>;` sits elsewhere in the module never literally
///    contains the return-type text the old check looked for. Fixed by resolving any `type X = …;`
///    alias in `source` whose right-hand side normalizes to `Result<(),UnlockFailure>` (or to
///    `Result<(), EnrolFailure>`, dig-app#235/#342's second verdict-threading return type) and
///    accepting `X` as an equivalent return type.
fn enrolling_custodian_methods_from(source: &str) -> Vec<String> {
    let trait_start = source
        .find("pub trait AccountCustodian {")
        .expect("the AccountCustodian trait is declared in dig-app-core");
    let trait_body = &source[trait_start..];
    // The trait's own closing brace: the first `}` in column zero after the declaration.
    let trait_end = trait_body
        .find("\n}")
        .expect("the AccountCustodian trait declaration is closed");

    let flat = |item: &str| -> String {
        // Doc comments precede almost every real item and can contain arbitrary prose — including,
        // for this very trait, the words "Result" and "UnlockFailure" in plain sentences — so they
        // are dropped by LINE before whitespace is collapsed, never matched against.
        item.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .flat_map(|line| line.split_whitespace())
            .collect::<Vec<_>>()
            .join(" ")
    };
    // Two verdict-threading return types today (dig-app#358 + dig-app#235/#342): the trait's own
    // documentation is the source of truth for which types count, not a list maintained here in
    // parallel with it — see the doc comment on `AccountCustodian` if a third one is ever added.
    let verdict_results: Vec<String> = ["Result<(), UnlockFailure>", "Result<(), EnrolFailure>"]
        .into_iter()
        .map(flat)
        .collect();
    let aliases_naming_a_verdict = result_type_aliases(source, &verdict_results);

    trait_body[..trait_end]
        // Every trait item declared without a body (this trait has no default bodies) ends in
        // exactly one `;`, and a rustfmt wrap can only add whitespace WITHIN an item, never move
        // that terminator — so splitting here survives any line-wrapping of the signature.
        .split(';')
        .filter_map(|item| {
            let flat_item = flat(item);
            // The LAST `"fn "` in the flattened item, not a strict prefix: the very first item in
            // the trait also carries the `pub trait AccountCustodian {` opening on the same
            // semicolon-delimited chunk, which a prefix check would reject outright.
            let sig_at = flat_item.rfind("fn ")?;
            let name = flat_item[sig_at + 3..].split('(').next()?.to_string();
            let names_a_verdict = verdict_results
                .iter()
                .any(|verdict| flat_item.contains(verdict))
                || aliases_naming_a_verdict
                    .iter()
                    .any(|alias| flat_item.ends_with(&format!("-> {alias}")));
            names_a_verdict.then_some(name)
        })
        .collect()
}

/// Every `type NAME = …;` alias in `source` whose right-hand side normalizes to one of
/// `verdict_results` (whitespace collapsed) — the set [`enrolling_custodian_methods_from`] accepts
/// as equivalent to spelling a verdict-threading result type out.
fn result_type_aliases(source: &str, verdict_results: &[String]) -> Vec<String> {
    source
        .split(';')
        .filter_map(|item| {
            let flat_item: String = item
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .flat_map(|line| line.split_whitespace())
                .collect::<Vec<_>>()
                .join(" ");
            let rest = flat_item.strip_prefix("type ")?;
            let (name, rhs) = rest.split_once('=')?;
            let rhs = rhs.trim();
            verdict_results
                .iter()
                .any(|verdict| rhs == verdict)
                .then(|| name.trim().to_string())

/// The source text of the shell's implementation of `name`, from its signature to its closing brace.
///
/// Brace-counted rather than line-sliced so a nested block cannot end the body early and quietly shrink
/// what the assertion above inspects.
fn shell_method_body(code: &str, name: &str) -> String {
    let at = code
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("the shell implements `{name}`"));
    let body = &code[at..];
    let open = body
        .find('{')
        .unwrap_or_else(|| panic!("`{name}` has a body"));
    let mut depth = 0usize;
    for (offset, ch) in body[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return body[..open + offset + 1].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("`{name}` has an unbalanced body")
}

/// The `UnlockFailure` VARIANTS a snippet names, e.g. `UnlockFailure::Refused`.
///
/// A path whose last segment starts lower-case — `UnlockFailure::from` — is a conversion, which THREADS
/// a verdict rather than choosing one, so it is not a hit. Distinguishing the two is the whole point:
/// banning the type name outright would forbid the correct shape along with the broken one.
///
/// # Two evasions this closes (dig-app#358)
///
/// 1. **A fully-qualified verdict path.** `<UnlockFailure>::Refused` is valid Rust — the angle
///    brackets are the fully-qualified-path form every type accepts, not only a trait-disambiguation
///    syntax — and it contains no literal `"UnlockFailure::"` substring at all, so the plain scan
///    below never sees it. Normalized back to the plain spelling before scanning.
/// 2. **A hard-coded value laundered through `::from`.** `UnlockFailure::from(SetupRefusal::Declined)`
///    is a `from` call in SHAPE, which the rule above correctly treats as threading — but its
///    argument is a bare, qualified enum-variant LITERAL, not a value carried in from the caller
///    (that would be a lowercase identifier, e.g. `UnlockFailure::from(refusal)`, dig-app's own
///    production shape at `bin/dig-app.rs:1497`). Choosing which fixed variant to convert is exactly
///    as deliberate as spelling the target variant directly, so this counts it too.
fn named_verdicts(snippet: &str) -> Vec<String> {
    // `<Type>::Variant` is the fully-qualified form of `Type::Variant`; collapsing it first lets the
    // rest of this function look for one spelling instead of two.
    let normalized = snippet.replace("<UnlockFailure>::", "UnlockFailure::");

    let mut hits: Vec<String> = normalized
        .match_indices("UnlockFailure::")
        .filter_map(|(at, marker)| {
            let name = normalized[at + marker.len()..]
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()?;
            name.starts_with(char::is_uppercase)
                .then(|| name.to_string())
        })
        .collect();

    for (at, marker) in normalized.match_indices("UnlockFailure::from(") {
        let args = &normalized[at + marker.len()..];
        let Some(close) = args.find(')') else {
            continue;
        };
        let arg = args[..close].trim();
        // A THREADED conversion passes a variable — a bare lowercase identifier, no path segments.
        // Anything starting upper-case with a `::` in it is a hard-coded source variant chosen right
        // there, not a value the caller handed in.
        if arg.contains("::") && arg.starts_with(char::is_uppercase) {
            hits.push(arg.to_string());
        }
    }

    hits
}

/// The at-rest consequence of a failed unlock is derived in the library, never written here.
///
/// `OpenAttempt::Wedged` is the single value that reaches the window whose only remedy is to replace
/// the account. While that mapping was one line in this test-free target, changing it left the whole
/// suite green and clippy silent.
#[test]
fn the_destructive_state_is_never_assigned_in_the_binary() {
    let code = tray_code();

    assert!(
        code.contains("attempt_after(failure)"),
        "the unlock arm must derive the at-rest state with `boot::attempt_after`"
    );
    assert!(
        !code.contains("OpenAttempt::Wedged"),
        "the state whose remedy destroys the account is being assigned in a target no test can reach"
    );
}

/// A fake trait source, standing in for `AccountCustodian`, with ONE arm's signature wrapped across
/// lines the way rustfmt does past 100 columns — exactly what the real trait's ~78-column arms are
/// one edit away from acquiring.
///
/// **Proves:** [`enrolling_custodian_methods_from`] finds `enrol_new` even though its return type
/// sits on its own line — the parse evasion named in dig-app#358 item 2. Before the fix, the
/// per-LINE scan never saw `"fn "` and `"Result<(), UnlockFailure>"` on one line and reported this
/// arm as ordinary, silently exempting it from `every_enrolling_custodian_arm_threads_its_verdict`.
#[test]
fn a_rustfmt_wrapped_signature_still_counts_as_an_enrolling_arm() {
    let source = "pub trait AccountCustodian {\n\
        fn lock_current(&self);\n\
        fn enrol_new(\n\
            &self,\n\
        )\n\
            -> Result<(), UnlockFailure>;\n\
        fn reopen(&self);\n\
    }\n";

    let arms = enrolling_custodian_methods_from(source);
    assert!(
        arms.iter().any(|a| a == "enrol_new"),
        "a wrapped signature was not recognised as an enrolling arm: {arms:?}"
    );
}

/// A fake trait source where the enrolling arm's return type is a TYPE ALIAS of
/// `Result<(), UnlockFailure>` rather than the literal spelling.
///
/// **Proves:** [`enrolling_custodian_methods_from`] resolves the alias — the parse evasion named in
/// dig-app#358 item 2's second half. Before the fix, the literal-text check never matched
/// `-> EnrolResult` and the arm went uncovered.
#[test]
fn a_type_aliased_return_still_counts_as_an_enrolling_arm() {
    let source = "type EnrolResult = Result<(), UnlockFailure>;\n\
        pub trait AccountCustodian {\n\
        fn lock_current(&self);\n\
        fn enrol_new(&self) -> EnrolResult;\n\
        fn reopen(&self);\n\
    }\n";

    let arms = enrolling_custodian_methods_from(source);
    assert!(
        arms.iter().any(|a| a == "enrol_new"),
        "a type-aliased return was not recognised as an enrolling arm: {arms:?}"
    );
}

/// **Proves:** `named_verdicts` catches a fully-qualified verdict path, `<UnlockFailure>::Refused` —
/// valid Rust that spells the same value `UnlockFailure::Refused` does, with no literal
/// `"UnlockFailure::"` substring anywhere in the source text (dig-app#358 item 2's third evasion).
#[test]
fn a_fully_qualified_verdict_path_is_still_caught() {
    let hits = named_verdicts("Err(<UnlockFailure>::Refused)");
    assert_eq!(
        hits,
        vec!["Refused".to_string()],
        "a fully-qualified path evaded the naming check"
    );
}

/// **Proves:** `named_verdicts` catches a verdict hard-coded through a `::from` conversion —
/// `UnlockFailure::from(SetupRefusal::Declined)` picks `Declined` exactly as deliberately as writing
/// `UnlockFailure::Declined` would, and unlike a real threaded call the argument is not a value the
/// caller handed in. This is the false negative dig-app#358 measured directly: before the fix,
/// `named_verdicts` reported zero results for this exact snippet.
#[test]
fn a_verdict_hardcoded_through_from_is_still_caught() {
    let hits = named_verdicts("Err(UnlockFailure::from(SetupRefusal::Declined))");
    assert!(
        !hits.is_empty(),
        "UnlockFailure::from(SetupRefusal::Declined) named a fixed verdict and was missed"
    );
}

/// **Proves the companion property:** a GENUINELY threaded `::from` call — the production shape at
/// `bin/dig-app.rs:1497`, `UnlockFailure::from(refusal)` — is NOT flagged. Tightening the check above
/// must not turn real threading into a false positive that would make this whole test suite unusable.
#[test]
fn a_genuinely_threaded_from_call_is_not_flagged() {
    let hits = named_verdicts("Err(UnlockFailure::from(refusal))");
    assert!(
        hits.is_empty(),
        "a threaded conversion was wrongly reported as naming a verdict: {hits:?}"
    );
}
