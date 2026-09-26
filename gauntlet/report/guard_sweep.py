#!/usr/bin/env python3
"""Mutate every guard in the validator and report which ones no control catches.

A guard nobody tests is a guard that can stop firing without anyone noticing,
and the whole page is an argument against exactly that. So this walks every
`Finding("CODE"` site, renames the code so that guard effectively disappears,
runs the controls, and records whether anything went red.

TWO TRAPS, BOTH HIT WHILE WRITING IT.

The first run reported 42 of 44 guards unguarded. That was false: the mutation
was a literal string replace of `Finding("CODE"` and most calls in the validator
are written across two lines, so the stimulus never applied and the suite stayed
green for the most boring possible reason. A green mutation row is a harness
defect until the stimulus is proven, exactly like a red one. Hence the assert
below: if the substitution does not change the file, this aborts rather than
reporting a comfortable number.

The second: bytecode caching can run the previous mutant and hand back kills
that belong to a different run, so the sweep clears `__pycache__` and runs with
bytecode writing off.

Exit 0 only when every guard is covered.
"""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
VALIDATOR = HERE / "validate.py"
TESTS = HERE / "tests"


def run_controls() -> bool:
    """True when the controls are green."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(TESTS), "-q", "--no-header",
         "--tb=no", "-p", "no:cacheprovider"],
        capture_output=True, text=True, cwd=HERE,
        env={**__import__("os").environ, "PYTHONDONTWRITEBYTECODE": "1"})
    return result.returncode == 0


def main() -> int:
    for cache in HERE.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)

    original = VALIDATOR.read_text()
    codes = sorted(set(re.findall(r'Finding\(\s*"([A-Z_]+)"', original)))
    if not codes:
        print("no guards found; the sweep cannot pass vacuously", file=sys.stderr)
        return 2

    # A red baseline makes every kill meaningless, so it is checked first.
    if not run_controls():
        print("BASELINE IS RED. A kill count over a failing suite is not a kill "
              "count; fix the suite before reading anything below.", file=sys.stderr)
        return 2

    uncaught = []
    try:
        for code in codes:
            pattern = re.compile(r'(Finding\(\s*)"' + code + r'"')
            mutated, count = pattern.subn(r'\1"NEUTERED"', original)
            if count == 0 or mutated == original:
                print(f"STIMULUS NOT APPLIED for {code}; aborting rather than "
                      "reporting a number this sweep did not measure",
                      file=sys.stderr)
                return 2
            VALIDATOR.write_text(mutated)
            if run_controls():
                uncaught.append(code)
    finally:
        VALIDATOR.write_text(original)

    print(f"guards {len(codes)} · caught {len(codes) - len(uncaught)} · "
          f"uncaught {len(uncaught)}")
    for code in uncaught:
        print(f"  UNCAUGHT {code}")
    return 1 if uncaught else 0


if __name__ == "__main__":
    raise SystemExit(main())
