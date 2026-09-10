//! Shared `#[cfg(test)]` source-scanning helpers used by more than one `rewards` test module --
//! [`super::pane`]'s hardcoded-English guard and [`super::clawback`]'s key-isolation guard
//! (dig_ecosystem#3281 plan step 6: "an in-file source-scanning string-literal extractor already
//! exists ... reuse it, do not write a second"). Moved out of `pane.rs` verbatim so both share the
//! ONE implementation rather than each carrying its own.

#![cfg(test)]

/// Slices `src` from `start_marker` (a `fn ...` signature) to `end_marker` (the next function's
/// signature) -- an explicit pair per caller, deliberately not a generic "next `fn`" scan (see
/// [`string_literals`]'s doc for why).
pub(crate) fn function_body<'a>(src: &'a str, start_marker: &str, end_marker: &str) -> &'a str {
    let start = src
        .find(start_marker)
        .unwrap_or_else(|| panic!("{start_marker} not found in source"));
    let rest = &src[start..];
    let end = rest
        .find(end_marker)
        .unwrap_or_else(|| panic!("{end_marker} not found after {start_marker} in source"));
    &rest[..end]
}

/// Every `"..."` string literal in `body`'s CODE lines, naively (no escape handling -- none of this
/// crate's guarded literals need it). Comment lines (`//`/`///`) are skipped first -- a quoted
/// phrase inside a doc comment is not a Rust string literal and must not trip a caller's guard.
///
/// Returns owned `String`s, not `&str`s borrowed from the local `code_only` buffer: an earlier
/// revision of this function (when it lived only in `pane.rs`) borrowed from that buffer via
/// `unsafe { std::mem::transmute }` to escape the borrow checker, which is undefined behaviour --
/// `code_only` drops at the end of the function, so every caller was reading freed memory
/// (dig_ecosystem#3253 adversarial gate, finding 2). There is no reason to borrow here at all.
pub(crate) fn string_literals(body: &str) -> Vec<String> {
    let code_only: String = body
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut out = Vec::new();
    let mut rest: &str = &code_only;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else {
            break;
        };
        out.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    out
}
