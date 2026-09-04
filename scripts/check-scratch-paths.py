#!/usr/bin/env python3
"""check-scratch-paths.py -- CI guard for dig-app#178 / dig-app#175.

Lanes anchor their branch with a stub commit before reading anything, so a
watchdog death or a session cap leaves a pushed branch to resume from. That
rule is correct and stays. What was missing is that nothing REMOVED the
anchor afterwards: thirteen lane-scratch paths rode into `main` inside
squashes whose reviewer was reading the substantive diff. A file whose entire
content says it is scratch is exactly what a reviewer's eye skips.

This guard scans the TRACKED TREE (`git ls-files`), not the PR diff.

Scanning the tree is strictly stronger than scanning the diff and much less
fragile. A diff check needs the base ref fetched, which a shallow CI clone
does not have by default -- and a guard that silently degrades to "no base,
nothing to compare, pass" is the failure mode this whole ticket is about.
Anything a diff check would catch is, by construction, in the tree of the
merge commit; scanning the tree also catches a path that arrived by any other
route (a force-push, a bad rebase, a revert of the cleanup). `main` is clean
as of this commit, so the tree scan is an INVARIANT rather than a property of
one diff.

Deliberately NOT a .gitignore-only fix. An ignore entry stops `git add -A`
from sweeping a scratch file up, which is worth having and is applied
alongside this, but it does not stop `git add -f` and it cannot see a file
already tracked. The load-bearing half is this check: a lane may still push
an anchor to survive a cap, and CI then tells it to delete the anchor in its
own PR -- which is exactly what dig-app#177 did by hand.

Exit 0 when the tree is clean, 1 when it is not (naming every offender and
the rule it broke), 2 when the scan could not be trusted.
"""

from __future__ import annotations

import re
import subprocess
import sys
from typing import Iterable, NamedTuple

# A tracked tree this small means `git ls-files` did not really run (wrong cwd,
# not a repo, a shell quoting accident). A guard that scans zero files reports
# a clean tree, which is indistinguishable from success -- so refuse instead.
# The repo tracks ~620 files; 100 is far below any plausible real checkout and
# far above any accidental one.
MIN_TRACKED_FILES = 100


class Rule(NamedTuple):
    """One scratch-path shape, with the reason it is banned."""

    pattern: re.Pattern[str]
    why: str


# Each rule is anchored at the repo root: these are root-level lane artifacts,
# and a nested `docs/lane-notes.md` is somebody's real documentation.
RULES: tuple[Rule, ...] = (
    Rule(
        re.compile(r"^\.lane(/|$)"),
        "lane scratch directory / anchor (`.lane`, `.lane/...`)",
    ),
    Rule(
        re.compile(r"^\.lane-"),
        "lane anchor stub (`.lane-<ticket>`, `.lane-<ticket>-<stage>`)",
    ),
    Rule(
        re.compile(r"^LANE(\.md$|-)"),
        "lane notes (`LANE.md`, `LANE-<ticket>.md`)",
    ),
    Rule(
        re.compile(r"^\.loop(/|$)"),
        "loop runtime state (`.loop/<ticket>-anchor.txt`)",
    ),
    Rule(
        re.compile(r"^\.(own|pr-body)\.md$"),
        "lane-private scratch (`.own.md`, `.pr-body.md`)",
    ),
)


def offenders(paths: Iterable[str]) -> list[tuple[str, str]]:
    """Return `(path, why)` for every path matching a banned scratch shape.

    Pure over its input so the guard's own test suite can exercise it on
    synthetic path lists without touching git or the filesystem.
    """
    found: list[tuple[str, str]] = []
    for path in paths:
        normalized = path.strip().replace("\\", "/")
        if not normalized:
            continue
        for rule in RULES:
            if rule.pattern.search(normalized):
                found.append((normalized, rule.why))
                break
    return found


def tracked_files(repo_root: str) -> list[str]:
    """Every path git tracks at `repo_root`, one per line."""
    completed = subprocess.run(
        ["git", "-C", repo_root, "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in completed.stdout.splitlines() if line.strip()]


def main(argv: list[str]) -> int:
    repo_root = argv[1] if len(argv) > 1 else "."

    try:
        paths = tracked_files(repo_root)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"check-scratch-paths: could not list tracked files: {exc}", file=sys.stderr)
        return 2

    if len(paths) < MIN_TRACKED_FILES:
        print(
            f"check-scratch-paths: only {len(paths)} tracked files found at "
            f"{repo_root!r} (expected at least {MIN_TRACKED_FILES}). The scan did "
            "not run against a real checkout; refusing to report a clean tree.",
            file=sys.stderr,
        )
        return 2

    found = offenders(paths)
    if not found:
        print(f"check-scratch-paths: OK -- {len(paths)} tracked files, no lane scratch.")
        return 0

    print(
        f"check-scratch-paths: {len(found)} lane-scratch path(s) are tracked in this tree:",
        file=sys.stderr,
    )
    for path, why in found:
        print(f"  {path}\n      banned as: {why}", file=sys.stderr)
    print(
        "\nLane anchors are working state, not product. Push-early is correct and stays --\n"
        "but the anchor must be deleted in the lane's own PR before merge. Prefer anchoring\n"
        "with a real stub commit (a version bump) over a scratch file, so there is nothing\n"
        "to clean up afterwards.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
