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
    let trait_start = source
        .find("pub trait AccountCustodian {")
        .expect("the AccountCustodian trait is declared in dig-app-core");
    let trait_body = &source[trait_start..];
    // The trait's own closing brace: the first `}` in column zero after the declaration.
    let trait_end = trait_body
        .find("\n}")
        .expect("the AccountCustodian trait declaration is closed");

    trait_body[..trait_end]
        .lines()
        .filter_map(|line| {
            let signature = line.trim();
            let name = signature.strip_prefix("fn ")?.split('(').next()?;
            (signature.contains("Result<(), UnlockFailure>")
                || signature.contains("Result<(), EnrolFailure>"))
            .then(|| name.to_string())
        })
        .collect()
}

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
fn named_verdicts(snippet: &str) -> Vec<&str> {
    snippet
        .match_indices("UnlockFailure::")
        .filter_map(|(at, marker)| {
            let name = snippet[at + marker.len()..]
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()?;
            name.starts_with(char::is_uppercase).then_some(name)
        })
        .collect()
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
