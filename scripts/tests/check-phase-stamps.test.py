#!/usr/bin/env python3
"""Tests for scripts/check-phase-stamps.py -- the CI gate that fails a build when
a `Phase` variant (dig-app's pump_vigil.rs) is stamped only by test code (dig-app#101).

Each case builds a synthetic `<root>/crates/dig-app/src/...` tree in a temp
directory and runs the real script against it as a subprocess -- black-box,
exactly the way CI invokes it -- rather than importing its functions, so a
bug in argument handling or path resolution would be caught here too.

Run: python3 scripts/tests/check-phase-stamps.test.py
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = HERE.parent / "check-phase-stamps.py"

failures = 0


def run_gate(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GATE), str(root)],
        capture_output=True,
        text=True,
        timeout=10,  # a hang here must go RED, not sit forever -- CLAUDE.md's own trap
    )


def write_tree(root: Path, pump_vigil_body: str, extra_files: dict[str, str] | None = None) -> None:
    """Lay out <root>/crates/dig-app/src/pump_vigil.rs plus any extra source files."""
    src = root / "crates" / "dig-app" / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "pump_vigil.rs").write_text(pump_vigil_body, encoding="utf-8")
    for rel, body in (extra_files or {}).items():
        path = src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


# A minimal but realistic enum declaration, matching pump_vigil.rs's own shape
# (doc comments interleaved, `Name = N,` lines, a bare `}` terminator).
ENUM_TWO_VARIANTS = """\
pub enum Phase {
    /// first
    Alpha = 0,
    /// second
    Beta = 1,
}
"""


def expect(name: str, want_exit: int, root: Path, want_substring: str | None = None) -> None:
    global failures
    result = run_gate(root)
    ok = result.returncode == want_exit
    if ok and want_substring is not None:
        ok = want_substring in result.stdout or want_substring in result.stderr
    if ok:
        print(f"ok   {name}")
    else:
        failures += 1
        print(f"FAIL {name}: exit={result.returncode} want={want_exit}")
        print(f"  stdout: {result.stdout!r}")
        print(f"  stderr: {result.stderr!r}")


with tempfile.TemporaryDirectory() as tmp:
    tmp_path = Path(tmp)

    # Case 1: both variants stamped in production via .enter() / .during() -- PASS.
    # This is the at-bound case (exactly one stamp each), not an over-stamped fixture --
    # a fixture with three stamps per variant could pass while a real single-stamp
    # regression would not, so the fixture must match the real shape exactly.
    root = tmp_path / "case1"
    write_tree(
        root,
        ENUM_TWO_VARIANTS,
        {
            "bin/app.rs": (
                "fn tick(canvas: &Heartbeat) {\n"
                "    canvas.enter(Phase::Alpha);\n"
                "    canvas.during(Phase::Beta, || {});\n"
                "}\n"
            )
        },
    )
    expect("both variants stamped in production -> PASS", 0, root)

    # Case 2: Beta is stamped ONLY inside #[cfg(test)] mod tests -- this is the exact
    # dig-app#97/#101 shape (a test can stamp the phase itself) and MUST fail.
    root = tmp_path / "case2"
    write_tree(
        root,
        ENUM_TWO_VARIANTS,
        {
            "bin/app.rs": (
                "fn tick(canvas: &Heartbeat) {\n"
                "    canvas.enter(Phase::Alpha);\n"
                "}\n"
                "\n"
                "#[cfg(test)]\n"
                "mod tests {\n"
                "    use super::*;\n"
                "\n"
                "    #[test]\n"
                "    fn beta_is_reachable() {\n"
                "        let canvas = Heartbeat::new();\n"
                "        canvas.during(Phase::Beta, || {});\n"
                "    }\n"
                "}\n"
            )
        },
    )
    expect("variant stamped only by tests -> FAIL naming it", 1, root, "Phase::Beta")

    # Case 3: Beta has NO stamp anywhere, production or test -- also FAIL, same as case 2's
    # visible symptom, proving the guard does not depend on test code existing at all.
    root = tmp_path / "case3"
    write_tree(
        root,
        ENUM_TWO_VARIANTS,
        {"bin/app.rs": "fn tick(canvas: &Heartbeat) {\n    canvas.enter(Phase::Alpha);\n}\n"},
    )
    expect("variant stamped nowhere -> FAIL naming it", 1, root, "Phase::Beta")

    # Case 4: resting_at() is a legitimate stamp form (the structural resting-phase
    # constructors, e.g. Heartbeat::state_loop() in the real crate) -- must count.
    root = tmp_path / "case4"
    write_tree(
        root,
        ENUM_TWO_VARIANTS,
        {
            "bin/app.rs": (
                "impl Heartbeat {\n"
                "    pub fn state_loop() -> Self {\n"
                "        Self::resting_at(Phase::Alpha, Instant::now())\n"
                "    }\n"
                "    pub fn render_loop() -> Self {\n"
                "        Self::resting_at(Phase::Beta, Instant::now())\n"
                "    }\n"
                "}\n"
            )
        },
    )
    expect("resting_at() counts as a production stamp -> PASS", 0, root)

    # Case 5: attribute and item share ONE physical line (`#[cfg(test)] fn f() { .. }`)
    # -- a shape rustfmt does not produce in this repo today, but the scanner must not
    # silently mis-track brace depth if it ever does. Beta's ONLY stamp sits in that
    # single-line test fn, so this must still FAIL.
    root = tmp_path / "case5"
    write_tree(
        root,
        ENUM_TWO_VARIANTS,
        {
            "bin/app.rs": (
                "fn tick(canvas: &Heartbeat) {\n"
                "    canvas.enter(Phase::Alpha);\n"
                "}\n"
                "#[cfg(test)] fn stamp_beta(c: &Heartbeat) { c.enter(Phase::Beta); }\n"
            )
        },
    )
    expect("attribute sharing a line with its item -> still excluded", 1, root, "Phase::Beta")

    # Case 6: a brace-LESS test item (mirrors pump_vigil.rs's own `#[cfg(test)] const
    # ALL: [Self; 2] = [...];`) must not leak its "armed" state into the code that
    # follows it. Beta's only real stamp sits in the line immediately after the const,
    # so if the scanner stayed stuck waiting for a brace, that stamp would be wrongly
    # excluded and this would false-FAIL -- the exact bug class the brace-vs-semicolon
    # branch exists to prevent.
    root = tmp_path / "case6"
    write_tree(
        root,
        ENUM_TWO_VARIANTS,
        {
            "bin/app.rs": (
                "impl Phase {\n"
                "    #[cfg(test)]\n"
                "    const ALL: [Self; 2] = [\n"
                "        Self::Alpha,\n"
                "        Self::Beta,\n"
                "    ];\n"
                "}\n"
                "fn tick(canvas: &Heartbeat) {\n"
                "    canvas.enter(Phase::Alpha);\n"
                "    canvas.enter(Phase::Beta);\n"
                "}\n"
            )
        },
    )
    expect("brace-less test const does not swallow the next real stamp -> PASS", 0, root)

    # Case 7: a stamp call inside a `//` comment must NOT count -- otherwise a mention
    # in a doc comment ("see canvas.during(Phase::Beta, ...)") would satisfy the guard
    # without any code ever running it.
    root = tmp_path / "case7"
    write_tree(
        root,
        ENUM_TWO_VARIANTS,
        {
            "bin/app.rs": (
                "fn tick(canvas: &Heartbeat) {\n"
                "    canvas.enter(Phase::Alpha);\n"
                "    // canvas.enter(Phase::Beta) used to be called here, see dig-app#97\n"
                "}\n"
            )
        },
    )
    expect("a stamp mentioned only in a comment -> FAIL naming it", 1, root, "Phase::Beta")

    # Case 8: the guard itself must not hang -- pure text scanning, no subprocess, no
    # test execution. Assert it finishes in well under its own 10s subprocess timeout.
    root = tmp_path / "case8"
    write_tree(
        root,
        ENUM_TWO_VARIANTS,
        {
            "bin/app.rs": (
                "fn tick(canvas: &Heartbeat) {\n"
                "    canvas.enter(Phase::Alpha);\n"
                "    canvas.enter(Phase::Beta);\n"
                "}\n"
            )
        },
    )
    started = time.monotonic()
    result = run_gate(root)
    elapsed = time.monotonic() - started
    if result.returncode == 0 and elapsed < 5.0:
        print(f"ok   completes quickly, no hang ({elapsed:.2f}s)")
    else:
        failures += 1
        print(f"FAIL completes quickly, no hang: exit={result.returncode} elapsed={elapsed:.2f}s")

    # Case 9: missing pump_vigil.rs entirely -- a usage/environment error (exit 2), not
    # a false PASS and not conflated with "a variant is missing a stamp" (exit 1).
    root = tmp_path / "case9"
    (root / "crates" / "dig-app" / "src").mkdir(parents=True)
    expect("missing pump_vigil.rs -> usage error, not a false pass", 2, root)

print()
if failures:
    print(f"{failures} FAILURE(S)")
    sys.exit(1)
print("all check-phase-stamps.py tests passed")
sys.exit(0)
