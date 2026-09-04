#!/usr/bin/env python3
"""check-phase-stamps.py -- CI guard for dig-app#101 / SPEC.md section 3.1b-lv.

SPEC.md requires: "A phase MUST be stamped by production code, not only by
tests." Nothing enforced that until this script existed. dig-app#97's
finding 1 (a render loop wedged in Shell_NotifyIcon froze the tray with zero
log lines) is reproduced by deleting BOTH `canvas.during(Phase::Presence,
...)` and `canvas.during(Phase::Repaint, ...)` in dig-app.rs -- and
`cargo test -p dig-app` stays fully green, because pump_vigil.rs's own tests
stamp those phases directly from #[cfg(test)] code. A test suite that can
stamp a phase itself can never notice production stopped doing so.

This is a source-scanning guard, not a control-flow prover -- the ticket's
own bar is "notice absence", not "prove reachability". For every `Phase`
variant declared in pump_vigil.rs, it requires at least one call shaped like
`enter(Phase::<Variant>`, `during(Phase::<Variant>`, or
`resting_at(Phase::<Variant>` -- the three call forms that actually write
Heartbeat's atomic phase stamp (see Heartbeat::{enter,during,resting_at} in
pump_vigil.rs) -- OUTSIDE any #[cfg(test)]/#[test]-attributed item. A
variant with zero such calls fails the build, naming it.

Test-code exclusion is a brace-depth scan (see find_test_line_numbers): it
does not parse Rust, so a brace hidden inside a string literal could in
principle confuse it. That is an accepted limit for a text-scanning guard --
this repo's own preference (recorded on dig-app#101 itself) is a type-level
fix where one is natural, falling back to scanning otherwise.

Usage: check-phase-stamps.py [repo-root]   (defaults to two dirs up from here)
Exit:  0 = every Phase variant has a non-test production stamp
       1 = at least one variant is stamped only by tests (or not at all)
       2 = usage/environment error (pump_vigil.rs missing, enum not found)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# The three call shapes that actually write Heartbeat's atomic phase stamp.
# Kept as a named tuple rather than inlined so the WHY is visible at the call
# site: `enter`/`during` are the dynamic per-call stamps both loops' real
# work goes through; `resting_at` is the constructor that bakes each loop's
# OWN resting phase (Phase::BetweenTicks, Phase::Waiting) in as the atomic's
# initial value -- those two variants are never `enter`ed/`during`ed in
# production, because being the resting default IS their stamp.
STAMP_CALLS = ("enter", "during", "resting_at")

#
# `\b` sits ONLY after the bare `test` alternative, not after `cfg\(test\)`: the latter
# is self-terminating on its literal `)`, so `#[cfg(testing)]` already cannot match it
# (the character after "test" must be `)`, not `i`). Putting `\b` after `cfg\(test\)` too
# was a real bug caught by this guard's own test suite (case 5): `)` and `]` are both
# non-word characters, so no word boundary exists between them, and `#[cfg(test)]` -- the
# ONLY form this codebase actually uses for the whole `mod tests` block -- silently never
# matched at all. It only "worked" by accident when an inner `#[test] fn` happened to sit
# tightly around the stamp; a stamp anywhere else inside an unmatched `#[cfg(test)]` mod
# (a helper fn, a `use`, a `const`) would have been misread as production code.
TEST_ATTR_RE = re.compile(r"^#\[\s*(cfg\(test\)|test\b)")
ENUM_START_RE = re.compile(r"^\s*pub enum Phase\s*\{")
ENUM_END_RE = re.compile(r"^\}\s*$")
VARIANT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\d+\s*,?\s*$")
STAMP_CALL_RE = re.compile(
    r"\b(?:" + "|".join(STAMP_CALLS) + r")\s*\(\s*Phase::([A-Za-z_][A-Za-z0-9_]*)"
)


def strip_line_comment(line: str) -> str:
    """Drop everything from an un-quoted `//` onward.

    Best-effort: tracks whether we are inside a `"..."` string so a `//`
    appearing in a literal (rare in this codebase's style -- mostly prose
    comments and log messages) does not truncate real code. Does not handle
    raw strings or backslash-escaped quotes beyond a single backslash --
    good enough for a text-scanning guard, not a Rust lexer.
    """
    in_string = False
    escaped = False
    for i, ch in enumerate(line):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
                return line[:i]
    return line


def phase_variants(pump_vigil_src: str) -> list[str]:
    """Read the `Phase` variant names straight out of its own enum declaration.

    Deliberately not a hand-maintained list here: pump_vigil.rs's own
    `Phase::ALL` doc comment records that a hand-written list is exactly how
    a variant gets ADDED without acquiring the assertions that keep it
    honest (the dig-app#97 shape). Reading the enum keeps this guard honest
    the same way, and never goes stale as variants are added or removed.
    """
    variants: list[str] = []
    in_enum = False
    for line in pump_vigil_src.splitlines():
        if not in_enum:
            if ENUM_START_RE.match(line):
                in_enum = True
            continue
        if ENUM_END_RE.match(line):
            break
        m = VARIANT_RE.match(line)
        if m:
            variants.append(m.group(1))
    if not variants:
        raise RuntimeError(
            "could not find any `pub enum Phase { ... }` variants in pump_vigil.rs "
            "-- this guard has gone stale, or the enum was renamed/relocated"
        )
    return variants


def find_test_line_numbers(lines: list[str]) -> set[int]:
    """Return the 0-based indices of every line inside a #[cfg(test)]/#[test] item.

    Handles both shapes this codebase actually uses: a brace-delimited item
    (`#[cfg(test)] mod tests { ... }`, tracked by brace depth) and a
    brace-less item (`#[cfg(test)] const ALL: [Self; 8] = [...];`, tracked by
    finding the terminating `;` before any `{` appears). An attribute and its
    item may share a line or sit on separate ones -- both are handled by not
    advancing past the attribute line before checking it for a brace/semicolon.
    """
    test_lines: set[int] = set()
    depth = 0
    test_depth: int | None = None
    armed_start: int | None = None  # line where a pending test attribute was seen

    for i, raw in enumerate(lines):
        code = strip_line_comment(raw)
        stripped = code.strip()

        if test_depth is None and armed_start is None and TEST_ATTR_RE.match(stripped):
            armed_start = i
            # No `continue` here: an attribute and its item can share one
            # physical line (`#[cfg(test)] fn f() {}`), so the brace/semicolon
            # scan below must still see the remainder of THIS line.

        if armed_start is not None and test_depth is None:
            brace_at = code.find("{")
            semi_at = code.find(";")
            if brace_at != -1 and (semi_at == -1 or brace_at < semi_at):
                # The attributed item opens a brace scope on this line. A
                # multi-line signature before it (no braces yet) belongs to
                # the test item too, so backfill armed_start..i-1.
                test_lines.update(range(armed_start, i))
                test_depth = depth  # depth BEFORE this line's own braces apply
            elif semi_at != -1:
                # A brace-less item (`use ...;`, a `const` array literal
                # closed by `];`) -- mark every line of it, including this
                # terminating one, and stop: no scope was opened, so there is
                # nothing to close.
                test_lines.update(range(armed_start, i + 1))
                armed_start = None
                depth += code.count("{") - code.count("}")
                continue
            else:
                continue  # still inside a multi-line signature or const body

        if test_depth is not None:
            test_lines.add(i)

        depth += code.count("{") - code.count("}")

        if test_depth is not None and depth <= test_depth:
            test_depth = None
            armed_start = None

    return test_lines


def production_stamps(path: Path) -> set[str]:
    """Every Phase variant this file stamps from OUTSIDE test code."""
    lines = path.read_text(encoding="utf-8").splitlines()
    test_lines = find_test_line_numbers(lines)
    found: set[str] = set()
    for i, raw in enumerate(lines):
        if i in test_lines:
            continue
        code = strip_line_comment(raw)
        for m in STAMP_CALL_RE.finditer(code):
            found.add(m.group(1))
    return found


def main(argv: list[str]) -> int:
    # Default: this file lives in <repo-root>/scripts/, so two parents up.
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parent.parent
    pump_vigil = root / "crates" / "dig-app" / "src" / "pump_vigil.rs"
    if not pump_vigil.is_file():
        print(f"check-phase-stamps: no such file: {pump_vigil}", file=sys.stderr)
        return 2

    try:
        variants = phase_variants(pump_vigil.read_text(encoding="utf-8"))
    except RuntimeError as exc:
        print(f"check-phase-stamps: {exc}", file=sys.stderr)
        return 2

    # Scan the whole dig-app crate source tree, not just the files that use
    # Phase today, so a future call site is covered without this guard
    # needing an update.
    src_root = root / "crates" / "dig-app" / "src"
    stamped: set[str] = set()
    for rs_file in sorted(src_root.rglob("*.rs")):
        stamped |= production_stamps(rs_file)

    missing = [v for v in variants if v not in stamped]
    if missing:
        print(
            "check-phase-stamps: FAIL -- stamped only by test code (or not stamped at all):",
            file=sys.stderr,
        )
        for v in missing:
            print(f"  Phase::{v}", file=sys.stderr)
        print(
            "  SPEC.md section 3.1b-lv: a phase MUST be stamped by production code, not only\n"
            "  by tests (dig-app#97/#101). Add an `enter(Phase::X)`/`during(Phase::X, ...)` call\n"
            "  outside #[cfg(test)], or a `resting_at(Phase::X, ...)` constructor.",
            file=sys.stderr,
        )
        return 1

    print(f"check-phase-stamps: OK -- all {len(variants)} Phase variants stamped by production code:")
    for v in variants:
        print(f"  Phase::{v}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
