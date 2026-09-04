#!/usr/bin/env python3
"""Adversarial test suite for scripts/check-scratch-paths.py (dig-app#178/#175).

A guard is only worth its required-check slot if it has been proven to go RED
on the thing it claims to catch AND to stay GREEN on the legitimate paths that
look like it. Both directions are exercised here: a guard proven only by the
positive case gets switched off the first time it fires on real work.

The negative cases are the load-bearing half. `docs/lane-notes.md`,
`crates/.../lifecycle.rs` and `src/planes.rs` all contain the substring the
rules match on; every rule is root-anchored so that none of them trips.

Run: python3 scripts/tests/check-scratch-paths.test.py
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

GUARD = Path(__file__).resolve().parent.parent / "check-scratch-paths.py"

_spec = importlib.util.spec_from_file_location("check_scratch_paths", GUARD)
assert _spec is not None and _spec.loader is not None
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


FAILURES: list[str] = []


def expect_flagged(path: str, note: str) -> None:
    """`path` MUST be reported as lane scratch."""
    found = guard.offenders([path])
    if not found:
        FAILURES.append(f"MISSED   {path!r} -- {note}")


def expect_clean(path: str, note: str) -> None:
    """`path` MUST NOT be reported; a false positive gets the guard disabled."""
    found = guard.offenders([path])
    if found:
        FAILURES.append(f"FALSE +  {path!r} -- {note} (matched: {found[0][1]})")


# --- RED: every path this ticket actually found committed on main -------------
# These thirteen are the real offenders from dig-app#178 + #175. If the guard
# ever stops flagging one of them it has silently stopped working.
for scratch in (
    ".lane/1841.md",
    ".lane/1966.md",
    ".lane/2038.md",
    ".lane/capture.ps1",
    ".lane-2398",
    ".lane-2398-s6",
    "LANE.md",
    "LANE-2993.md",
    "LANE-3038.md",
    "LANE-3041.md",
    "LANE-3077.md",
    "LANE-334.md",
    ".loop/2939-anchor.txt",
):
    expect_flagged(scratch, "shipped to main and had to be deleted by hand")

# --- RED: shapes the same habit produces next ---------------------------------
expect_flagged(".lane", "the bare anchor file")
expect_flagged(".lane-9999", "a future lane's extension-less anchor")
expect_flagged(".lane-2989.md", "the shape .gitignore already knew about")
expect_flagged(".loop/4321-anchor.txt", "a future loop anchor")
expect_flagged(".loop", "the bare loop state directory")
expect_flagged(".own.md", "lane-private scratch from the #329 batch")
expect_flagged(".pr-body.md", "lane-private scratch from the #329 batch")
expect_flagged(".lane\\2038.md", "a Windows-separated path must normalize")

# --- GREEN: real repo paths that share the substrings -------------------------
# Root-anchoring is what makes these safe. A guard that flagged any of them
# would be switched off within a day, which is worse than not having it.
expect_clean("docs/lane-notes.md", "somebody's real documentation, not at root")
expect_clean("crates/dig-app-core/src/account/lifecycle.rs", "contains 'lane'? no -- but near-miss prose")
expect_clean("src/planes.rs", "'lane' appears mid-word")
expect_clean("crates/dig-app-core/src/confirm/gui/window/pane/copy.rs", "'pane' is not 'lane'")
expect_clean("LANGUAGES.md", "starts with LAN, not LANE-")
expect_clean("LANES.md", "LANE followed by S, not '.md' or '-'")
expect_clean("scripts/lane-helper.sh", "a real tool would live in scripts/, not at root")
expect_clean(".github/workflows/ci.yml", "ordinary CI config")
expect_clean("Cargo.toml", "ordinary manifest")
expect_clean(".gitignore", "a dotfile that is not lane scratch")
expect_clean(".loopback/mod.rs", "'.loop' as a prefix of a longer segment must not match")

# --- the guard must refuse a scan it cannot trust -----------------------------
# A scan that walks zero files reports a clean tree, which is indistinguishable
# from success. dig-node's own lint hit exactly this, so the floor is asserted
# here rather than assumed.
if guard.MIN_TRACKED_FILES < 100:
    FAILURES.append(
        f"MIN_TRACKED_FILES is {guard.MIN_TRACKED_FILES}; a floor that low cannot "
        "distinguish a real checkout from an empty scan"
    )

# An empty input must produce no offenders (the floor, not `offenders`, is what
# turns "nothing scanned" into a failure -- keep the two responsibilities apart).
if guard.offenders([]) != []:
    FAILURES.append("offenders([]) should be empty; the empty-scan refusal belongs to main()")


if FAILURES:
    print(f"check-scratch-paths.test: {len(FAILURES)} failure(s):", file=sys.stderr)
    for failure in FAILURES:
        print(f"  {failure}", file=sys.stderr)
    sys.exit(1)

print("check-scratch-paths.test: OK -- all red and green cases behave as specified.")
