#!/usr/bin/env python3
"""Adversarial test suite for scripts/check-space-runs.py (dig-app#204).

The ticket sets the bar and states the reason: "The lint must fail on a
fixture containing a corrupted literal and pass on one containing a
legitimate `\\`-continuation. Both directions -- a lint proven only by the
positive case will be switched off the first time it fires on valid code."

The negative fixture is therefore the load-bearing half, and it is deliberately
harder than the positive one: a correct continuation, differing-pad column
alignment, an indented usage banner, a raw string, a lifetime, a char literal
holding a quote, an escaped quote, and a comment. Every one of those is a
construct that a naive source-line regex flags.

The threshold is pinned from BOTH sides. Four spaces must fire and three
must not; a bound tested only from below can confirm nothing but itself.

Run: python3 scripts/tests/check-space-runs.test.py
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GUARD = HERE.parent / "check-space-runs.py"
FIXTURES = HERE / "fixtures"

_spec = importlib.util.spec_from_file_location("check_space_runs", GUARD)
assert _spec is not None and _spec.loader is not None
guard = importlib.util.module_from_spec(_spec)
# Registered BEFORE exec: `@dataclass` resolves its annotations through
# `sys.modules[cls.__module__]`, which is None for a spec-loaded module that
# has not been registered, and fails with an opaque AttributeError.
sys.modules["check_space_runs"] = guard
_spec.loader.exec_module(guard)

FAILURES: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        FAILURES.append(message)


def scan(source: str, path: str = "crates/x/src/lib.rs") -> list:
    return guard.scan_text(path, source)


# ---------------------------------------------------------------------------
# The two fixtures the ticket asks for, byte for byte as they sit on disk.
# ---------------------------------------------------------------------------

corrupted = (FIXTURES / "space_run_corrupted.rs.fixture").read_text(encoding="utf-8")
legitimate = (FIXTURES / "space_run_legitimate.rs.fixture").read_text(encoding="utf-8")

corrupted_hits = scan(corrupted, "scripts/tests/fixtures/space_run_corrupted.rs")
legitimate_hits = scan(legitimate, "scripts/tests/fixtures/space_run_legitimate.rs")

# An EXACT count, not a floor: a floor would stay green if the guard started
# double-reporting a run, and the run lengths pin that each tear is measured
# at its true width rather than merely noticed.
check(
    [(h.line, h.run) for h in corrupted_hits] == [(17, 10), (21, 20), (24, 4), (30, 14), (36, 10)],
    f"the corrupted fixture holds five torn literals of 10/20/4/14/10 spaces; "
    f"the guard found {[(h.line, h.run) for h in corrupted_hits]}",
)
check(
    not legitimate_hits,
    "the legitimate fixture must produce NO findings; the guard flagged "
    + repr([(h.line, h.run, h.excerpt) for h in legitimate_hits]),
)

# The two strings the ticket measured as having SHIPPED must each be caught.
for shipped in ("can change what you typed", "been started"):
    check(
        any(shipped in h.excerpt for h in corrupted_hits),
        f"the shipped instance containing {shipped!r} was not flagged",
    )


# ---------------------------------------------------------------------------
# The bound, from both sides.
# ---------------------------------------------------------------------------

check(len(scan('let s = "stops    working";')) == 1, "four spaces must fire (the bound)")
check(not scan('let s = "stops   working";'), "three spaces must NOT fire (one under the bound)")
check(len(scan('let s = "stops     working";')) == 1, "five spaces must fire (over the bound)")


# ---------------------------------------------------------------------------
# The continuation, which is the entire reason values are evaluated.
# ---------------------------------------------------------------------------

check(
    not scan('let s = "hello \\\n             world";'),
    "a CORRECT backslash continuation must never fire -- rustc strips that "
    "indentation, so it is not in the value",
)
check(
    len(scan('let s = "hello\n             world";')) == 0,
    "a value line that BEGINS with spaces is an indented multi-line literal, "
    "not a torn sentence",
)


# ---------------------------------------------------------------------------
# Constructs a source-line regex gets wrong.
# ---------------------------------------------------------------------------

check(not scan('let s = r"raw    string";'), "a raw string cannot hold a lost continuation")
check(not scan('let s = r#"raw    hashed"#;'), "a hashed raw string likewise")
check(not scan('// a comment with a    run\n'), "comments are never scanned")
check(not scan('/* block with a    run */\n'), "block comments are never scanned")
check(not scan('/* /* nested */ with a    run */\n'), "nested block comments are handled")
check(
    not scan("fn f<'a>(s: &'a str) {}\nlet c = '\"';\n"),
    "a lifetime and a char literal holding a quote must not desynchronise the scanner",
)
check(
    len(scan('let s = "she said \\"no\\" and    meant it";')) == 1,
    "an escaped quote must not end the literal early",
)

# Column alignment: differing pads to one column is tabulation.
check(
    not scan('let s = "endpoint    {a}\\nlineage      {b}";'),
    "differing pads reaching one column is a layout column, not corruption",
)
# ...but two runs of the SAME length landing on one column is coincidence,
# which is what a big file full of 14-space tears produces.
check(
    len(scan('let s = "aaaa bbbb    x is torn\\ncccc dddd    y is torn";')) == 2,
    "equal-length pads at one column are coincidence, not tabulation, and "
    "must still be flagged",
)

# A run at a field boundary is formatting; a run between two words is a tear.
check(not scan('let s = "label    {value}";'), "a run before a placeholder is a field boundary")
check(not scan('let s = "label    : value";'), "a run before a separator is a field boundary")


# ---------------------------------------------------------------------------
# Test-context classification: reported, never fatal.
# ---------------------------------------------------------------------------

in_cfg_test = '#[cfg(test)]\nmod t {\n    fn f() { let s = "torn    sentence"; }\n}\n'
hits = scan(in_cfg_test)
check(len(hits) == 1 and hits[0].in_test, "a literal inside #[cfg(test)] must be marked in_test")

after_cfg_test = (
    '#[cfg(test)]\nmod t {\n    fn f() { let s = "a    b"; }\n}\n'
    'fn prod() { let s = "torn    sentence"; }\n'
)
hits = scan(after_cfg_test)
check(
    len(hits) == 2 and hits[0].in_test and not hits[1].in_test,
    "the test region must CLOSE at its brace; production code after it is "
    f"fatal, got {[(h.line, h.in_test) for h in hits]}",
)

hits = scan('let s = "torn    sentence";', "crates/x/tests/it.rs")
check(hits and hits[0].in_test, "anything under a tests/ directory is test copy")


# ---------------------------------------------------------------------------
# The guard must refuse a scan it cannot trust.
# ---------------------------------------------------------------------------

check(
    guard.MIN_FILES_SCANNED >= 20,
    f"MIN_FILES_SCANNED is {guard.MIN_FILES_SCANNED}; a floor that low cannot "
    "tell a real workspace from an empty scan",
)
check(guard.main(["x", str(FIXTURES)]) == 2, "a directory with too few .rs files must exit 2, not 0")


if FAILURES:
    print(f"check-space-runs.test: {len(FAILURES)} failure(s):", file=sys.stderr)
    for failure in FAILURES:
        print(f"  {failure}", file=sys.stderr)
    sys.exit(1)

print(
    f"check-space-runs.test: OK -- {len(corrupted_hits)} findings on the corrupted "
    "fixture, 0 on the legitimate one, bound pinned from both sides."
)
