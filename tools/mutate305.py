"""Prove each #305 test is load-bearing by reverting ONLY its fix, one at a time.

Every mutation is applied to a COPY of the file's committed bytes, the suite is run, and the
original bytes are restored from the in-memory copy — never by `git checkout`, which is destructive
on uncommitted work. The harness asserts the file is byte-identical again afterwards, because a
harness that under-reverts certifies the next run against a dirty tree.

A mutation whose replacement did not apply is reported as SKIPPED rather than as a pass: a silent
no-op replace goes green and reads exactly like "the fix works".
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MOD = ROOT / "crates/dig-app-core/src/updates/mod.rs"
WATCH = ROOT / "crates/dig-app-core/src/updates/watch.rs"

MUTATIONS = [
    (
        "unknown activation is reported as ACTIVE",
        MOD,
        '            _ => Self::Unknown,\n',
        '            _ => Self::Active,\n',
    ),
    (
        "the unknown sentence borrows the confident one",
        MOD,
        '            Self::Unknown => "Whether it is running yet could not be determined.",\n',
        '            Self::Unknown => "It is running now.",\n',
    ),
    (
        "a first sight ANNOUNCES instead of adopting",
        MOD,
        "        let Some(announced) = self.announced.as_mut() else {\n",
        "        let Some(announced) = self.announced.get_or_insert_with(Default::default).into() else {\n",
    ),
    (
        "the ledger is not updated after announcing",
        MOD,
        "        for component in news {\n            announced.insert(component.name.clone(), component.version.clone());\n        }\n",
        "        for _component in news {}\n",
    ),
    (
        "a beacon that cannot be asked is recorded as an empty observation",
        WATCH,
        "    let Some(json) = read() else {\n        return;\n    };\n",
        "    let json = read().unwrap_or_default();\n",
    ),
    (
        "the roll-up flattens every component onto the first activation",
        MOD,
        '        .map(|c| format!("• {} {} — {}", c.name, c.version, c.activation.short()))\n',
        '        .map(|c| format!("• {} {} — {}", c.name, c.version, news[0].activation.short()))\n',
    ),
    (
        "the name and version reach the toast un-neutralised",
        MOD,
        '        name: crate::confirm::neutralize_or(name, NAME_LIMIT, "an unnamed component"),\n',
        "        name: name.to_string(),\n",
    ),
]


def run_suite() -> tuple[bool, str]:
    result = subprocess.run(
        ["cargo", "test", "-p", "dig-app-core", "--lib", "updates::"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0, result.stdout + result.stderr


def main() -> int:
    baseline_ok, baseline_out = run_suite()
    if not baseline_ok:
        print("BASELINE IS RED — nothing below means anything")
        print(baseline_out[-3000:])
        return 2
    print("baseline: GREEN\n")

    verdicts = []
    for name, path, old, new in MUTATIONS:
        original = path.read_bytes()
        text = original.decode("utf-8")
        if text.count(old) != 1:
            verdicts.append((name, "SKIPPED — anchor matched %d times" % text.count(old)))
            continue
        path.write_bytes(text.replace(old, new).encode("utf-8"))
        try:
            ok, out = run_suite()
        finally:
            path.write_bytes(original)
            assert path.read_bytes() == original, "the revert did not restore the file"
        if ok:
            verdicts.append((name, "SURVIVED — no test catches this"))
        else:
            caught = [
                line.split()[1]
                for line in out.splitlines()
                if line.startswith("test ") and line.rstrip().endswith("FAILED")
            ]
            verdicts.append((name, "caught by " + (", ".join(caught) or "a compile error")))
        print("%-62s %s" % (name, verdicts[-1][1]))

    after_ok, _ = run_suite()
    print("\nsuite after every revert: %s" % ("GREEN" if after_ok else "RED — the tree is dirty"))
    return 0 if after_ok and all("SURVIVED" not in v and "SKIPPED" not in v for _, v in verdicts) else 1


if __name__ == "__main__":
    sys.exit(main())
