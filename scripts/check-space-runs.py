#!/usr/bin/env python3
"""check-space-runs.py -- CI guard for dig-app#204 (lost string continuations).

A Rust string literal continued with a trailing backslash renders correctly:
the backslash eats the newline AND the next line's indentation, so the value
is one clean sentence. When the backslash is lost -- an agent's own tooling
eating it on the way to disk, `cargo fmt` rejoining a wrapped literal, a
mechanical regex repair -- the indentation SURVIVES INSIDE THE STRING and
ships as user-facing copy:

    "Your profile is unchanged - you          can change what you typed"
    "DIG could not start this creation because one has already        been started"

Nothing catches it. `cargo fmt --check` passes, because it is valid
formatting of a valid literal. Clippy passes, because it is a valid literal.
A test asserting with `contains(...)` on a substring that does not span the
run passes too. Both shipped instances were caught by a person reading the
source. Measured 2026-08-18: 31 sites, 9 of them in shipped user-facing copy,
three separate agents hitting it in one session.

WHY THIS READS THE LITERAL'S VALUE, NOT THE SOURCE LINE
--------------------------------------------------------
This is the whole design, and getting it wrong is how such a lint gets
switched off within a week. A CORRECT continuation looks like this:

    let s = "hello \\
             world";

The second source line begins with thirteen spaces. A regex over source text
sees that run and fires -- on code that is completely correct.

Evaluating the VALUE removes the problem at its root rather than exempting
it. rustc strips that indentation before the string exists, so the correct
form has NO run in its value and CANNOT be flagged; only the broken form
keeps the indentation. dig-node's equivalent guard scans source lines and
pays for it with four hand-maintained exemption lists (excluded directories,
excluded line ranges, five named CLI-column files, a trailing-comment
carve-out). This one needs no file allowlist at all.

TWO STRUCTURAL RULES, NO ALLOWLIST
-----------------------------------
1. The run must be MID-LINE -- preceded by a non-space on the same line of
   the value. A value line that BEGINS with spaces is a deliberately indented
   multi-line literal (a usage banner, an embedded snippet). This is the
   ticket's own rule: "not at the start of a continuation line".

2. The run must not end at a LAYOUT COLUMN -- a column two or more lines in
   the same file pad to. Alignment is by definition repeated; that is what
   aligning means. A torn sentence lands wherever its prose happened to end,
   so two coinciding to the exact character needs the same accident twice.

Raw strings (r"...", r#"..."#) are skipped on the same principle rather than
as a favour: they have no escapes, so they cannot HAVE a lost continuation.
A run inside one was typed deliberately.

FATAL vs REPORTED
-----------------
Only non-test copy fails the build. Most known sites are test assertion
messages printed on failure, where the damage is cosmetic -- and the ticket
says plainly that failing the build on those "invites a bulk-suppression
commit that also suppresses the real ones". Test-context findings are
printed, loudly, and exit 0.

Exit 0 clean, 1 on user-facing corruption, 2 when the scan cannot be trusted.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

# A lost continuation leaves the source's own indentation, which in this
# codebase is 8-24 spaces. Four is the ticket's threshold and sits above any
# plausible intra-sentence typo (a double space after a full stop is two).
MIN_RUN = 4

# The workspace has hundreds of .rs files. A scan that reads a handful is a
# broken guard, not a passing one: it prints a clean tree and is otherwise
# indistinguishable from success. dig-node's equivalent uses > 20.
MIN_FILES_SCANNED = 20

SKIP_DIRS = frozenset({"target", ".git", "node_modules", ".gitnexus", "__pycache__"})


@dataclass(frozen=True)
class Literal:
    """One string literal recovered from a source file.

    `body_start`/`body_end` bracket the literal's body in the ORIGINAL source
    (excluding the quotes). They exist so a mechanical repair can locate a run
    in the source it must edit, rather than in the decoded value it found the
    run in -- the two differ wherever the literal contains an escape.
    """

    line: int
    value: str
    in_test: bool
    body_start: int
    body_end: int


@dataclass(frozen=True)
class Finding:
    """One mid-sentence space run inside a literal's value."""

    path: str
    line: int
    run: int
    excerpt: str
    in_test: bool


def _raw_string_open(text: str, i: int) -> tuple[int, str] | None:
    """If a raw-string literal opens at `i`, return `(body_start, terminator)`.

    Handles r", r#", r##" and their b/br byte-string spellings.
    """
    j = i
    if text.startswith("br", j):
        j += 2
    elif text[j] in ("r", "b"):
        j += 1
    else:
        return None
    hashes = 0
    while j < len(text) and text[j] == "#":
        hashes += 1
        j += 1
    if j >= len(text) or text[j] != '"':
        return None
    return j + 1, '"' + "#" * hashes


def _decode(body: str) -> str:
    """Evaluate a non-raw Rust string literal body to the value it denotes.

    Only two things need to be exact, because only two can create or destroy a
    space run: the backslash-newline continuation (which eats the newline and
    ALL following whitespace -- the entire reason a correct continuation
    cannot be flagged) and a backslash-escaped space. Every other escape
    collapses to one placeholder character, which is enough precisely because
    a placeholder is neither a space nor a newline, so it can neither invent
    nor hide a run.
    """
    out: list[str] = []
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= n:
            break
        esc = body[i]
        if esc == "\n":
            # The continuation: skip the newline and every following
            # whitespace character, exactly as rustc does.
            i += 1
            while i < n and body[i] in " \t\r\n":
                i += 1
            continue
        i += 1
        if esc == "n":
            out.append("\n")
        elif esc == "t":
            out.append("\t")
        elif esc == "r":
            out.append("\r")
        elif esc == "x":
            i += 2
            out.append("\x00")
        elif esc == "u":
            while i < n and body[i] != "}":
                i += 1
            i += 1
            out.append("\x00")
        else:
            out.append(" " if esc == " " else "\x00")
    return "".join(out)


def literals(text: str) -> Iterator[Literal]:
    """Yield every non-raw string literal in `text`, with its evaluated value.

    A hand-written scanner rather than a regex, because the states that must
    be skipped -- line comments, NESTING block comments, char literals, and
    lifetimes (`&'a str`, a lone quote that opens nothing) -- are not
    expressible as one. Raw strings are recognised only so they can be
    stepped over without their contents being mistaken for code.

    `#[cfg(test)]` and `#[test]` regions are tracked by brace depth, which is
    accurate here precisely because this scanner already knows which braces
    are inside strings and comments.
    """
    i = 0
    n = len(text)
    line = 1
    depth = 0
    test_depth: int | None = None
    pending_test_attr = False

    while i < n:
        c = text[i]

        if c == "\n":
            line += 1
            i += 1
            continue

        # -- comments ---------------------------------------------------
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if text.startswith("/*", i):
            nest = 1
            i += 2
            while i < n and nest:
                if text.startswith("/*", i):
                    nest += 1
                    i += 2
                elif text.startswith("*/", i):
                    nest -= 1
                    i += 2
                else:
                    if text[i] == "\n":
                        line += 1
                    i += 1
            continue

        # -- test-context attributes ------------------------------------
        if c == "#" and (
            text.startswith("#[cfg(test)]", i) or text.startswith("#[test]", i)
        ):
            pending_test_attr = True
            i += 2
            continue

        # -- braces, for test-region tracking ---------------------------
        if c == "{":
            depth += 1
            if pending_test_attr and test_depth is None:
                test_depth = depth
                pending_test_attr = False
            i += 1
            continue
        if c == "}":
            if test_depth is not None and depth == test_depth:
                test_depth = None
            depth -= 1
            i += 1
            continue

        # -- raw strings: skipped, but consumed as a unit ---------------
        if c in ("r", "b"):
            opened = _raw_string_open(text, i)
            if opened is not None:
                body_start, terminator = opened
                end = text.find(terminator, body_start)
                end = n if end == -1 else end
                line += text.count("\n", i, end)
                i = end + len(terminator)
                continue

        # -- char literal vs lifetime -----------------------------------
        if c == "'":
            if text.startswith("'\\", i):
                j = text.find("'", i + 2)
                i = n if j == -1 else j + 1
            elif i + 2 < n and text[i + 2] == "'":
                i += 3
            else:
                i += 1  # a lifetime; opens nothing
            continue

        # -- the string literal itself ----------------------------------
        if c == '"':
            start_line = line
            i += 1
            body_start = i
            while i < n:
                if text[i] == "\\":
                    if text[i + 1 : i + 2] == "\n":
                        line += 1
                    i += 2
                    continue
                if text[i] == '"':
                    break
                if text[i] == "\n":
                    line += 1
                i += 1
            yield Literal(
                line=start_line,
                value=_decode(text[body_start:i]),
                in_test=test_depth is not None,
                body_start=body_start,
                body_end=i,
            )
            i += 1
            continue

        i += 1


def _runs(value_line: str) -> Iterator[tuple[int, int]]:
    """Yield `(start, end)` for each run of 2+ spaces not at the line start.

    Two, not `MIN_RUN`: the SHORT runs are what reveal a layout column. On a
    `--help` screen the `-V, --version` row pads by two and `-h, --help` pads
    by five to reach the same description column, and a scan that only saw
    long runs would believe that column had been hit once.
    """
    i = 0
    n = len(value_line)
    while i < n:
        if value_line[i] != " ":
            i += 1
            continue
        start = i
        while i < n and value_line[i] == " ":
            i += 1
        if i - start >= 2 and start > 0 and i < n:
            yield start, i
        i += 1


def layout_columns(value_lines: list[str]) -> frozenset[int]:
    """Columns that two or more lines pad to -- deliberate tabulation.

    This is what lets the guard carry no allowlist. `examples/chain_probe.rs`
    prints seven `label{pad}{value}` rows whose values all begin at column 20;
    `argv.rs` aligns every flag description to column 17. Alignment is by
    definition REPEATED -- that is what aligning means -- whereas a torn
    sentence lands wherever its prose happened to end, so two of them
    coinciding to the exact character requires the same accident twice.

    dig-node's equivalent names five files and a line range by hand to cover
    these cases. A column count needs no maintenance and cannot go stale when
    a sixth file starts printing a table.

    The pads reaching the column must DIFFER in length, and that requirement
    is load-bearing rather than decorative. Padding of varying width to one
    column is what tabulation IS -- `endpoint` pads by 12 and `lineage` by 13
    to both reach column 20. Two runs of the SAME length landing on one column
    means only that two prefixes happened to be equally long, which is exactly
    what a file full of 14-space tears produces: an early draft of this rule
    counted bare collisions and silently exempted four real torn sentences in
    `shell.rs` and three in `window.rs`, because a big file gives coincidence
    plenty of chances.
    """
    widths: dict[int, set[int]] = {}
    for value_line in value_lines:
        for start, end in _runs(value_line):
            widths.setdefault(end, set()).add(end - start)
    return frozenset(col for col, pads in widths.items() if len(pads) >= 2)


def scan_text(path: str, text: str) -> list[Finding]:
    """Every mid-sentence run of `MIN_RUN`+ spaces in `text`'s literal values.

    Pure over its input so the guard's own suite can drive it with fixtures.
    """
    forced_test = "/tests/" in path.replace("\\", "/")

    found: list[Finding] = []
    for lit in literals(text):
        value_lines = lit.value.split("\n")
        # Layout columns are computed PER LITERAL, not per file. A table lives
        # inside one literal -- `argv.rs`'s whole `--help` screen is a single
        # `format!` whose rows pad by 2 and by 5 to reach one description
        # column. Widening the window to the file lets coincidence in with it:
        # over a 5,000-line file, unrelated 14-space tears find a same-column
        # partner easily, and a file-scoped version of this rule silently
        # exempted real torn sentences in dispatch.rs, shell.rs and window.rs.
        columns = layout_columns(value_lines)
        for value_line in value_lines:
            for start, end in _runs(value_line):
                if end - start < MIN_RUN or end in columns:
                    continue
                # A torn sentence is word-run-WORD. A run landing on `{`, `:`
                # or any other punctuation is a field boundary -- a value
                # slot in a banner, a key/value separator -- not a sentence
                # pulled apart. This deliberately trades one narrow miss (a
                # tear that happens to fall just before a `{}` placeholder)
                # for silence on every CLI table in the workspace, which is
                # the trade dig-app#204 asks for in as many words: failing on
                # cosmetic hits "invites a bulk-suppression commit that also
                # suppresses the real ones".
                if not value_line[end].isalnum():
                    continue
                found.append(
                    Finding(
                        path=path,
                        line=lit.line,
                        run=end - start,
                        excerpt=value_line[max(0, start - 30) : end + 30],
                        in_test=lit.in_test or forced_test,
                    )
                )
    return found


def rust_sources(root: Path) -> Iterator[Path]:
    """Every `.rs` file under `root`, skipping build output and vendored trees."""
    for path in sorted(root.rglob("*.rs")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else ".").resolve()

    scanned = 0
    findings: list[Finding] = []
    for path in rust_sources(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        findings.extend(scan_text(path.relative_to(root).as_posix(), text))

    if scanned <= MIN_FILES_SCANNED:
        print(
            f"check-space-runs: scanned {scanned} files under {root} (expected more "
            f"than {MIN_FILES_SCANNED}). A scan that reads nothing reports a clean "
            "tree, so this fails rather than passing vacuously.",
            file=sys.stderr,
        )
        return 2

    fatal = [f for f in findings if not f.in_test]
    reported = [f for f in findings if f.in_test]

    if reported:
        print(
            f"check-space-runs: {len(reported)} space run(s) in TEST copy "
            "(reported, not fatal -- these print only on an assertion failure):"
        )
        for f in reported:
            print(f"  {f.path}:{f.line}  {f.run} spaces  ...{f.excerpt.strip()}...")
        sys.stdout.flush()

    if fatal:
        print(
            f"check-space-runs: {len(fatal)} space run(s) of {MIN_RUN}+ inside NON-TEST "
            "string literals. This is the lost-continuation signature (dig-app#204) "
            "and this copy is user-reachable:",
            file=sys.stderr,
        )
        for f in fatal:
            print(
                f"  {f.path}:{f.line}  {f.run} spaces  ...{f.excerpt.strip()}...",
                file=sys.stderr,
            )
        print(
            "\nRejoin the sentence. If the literal must wrap, end the line with a "
            "backslash so rustc eats the newline and the indentation with it.",
            file=sys.stderr,
        )
        return 1

    print(f"check-space-runs: OK -- {scanned} .rs files scanned, no user-facing corruption.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
