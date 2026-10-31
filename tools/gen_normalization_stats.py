#!/usr/bin/env python3
"""Count the normalization techniques SUNGLASSES actually runs, from the code.

The README and the site said "17 normalization techniques". The number was typed
into stats/current.json by hand and nothing counted it. preprocessor.NORMALIZATION_STEPS
lists what the code undoes, one row per technique, 16 rows. This script counts
that list; it does not discover techniques on its own. What holds the list to
the code is tests/test_normalization_steps.py (a probe and a control per row, a
bare-name call guard on both lanes, and a pin on the source of the
normalization functions); its docstring says what that does not cover.

    python3 tools/gen_normalization_stats.py            # print the measurement
    python3 tools/gen_normalization_stats.py --write    # update stats/current.json

Deliberately stdlib only.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sunglasses.preprocessor import NORMALIZATION_STEPS  # noqa: E402


def measure(steps=NORMALIZATION_STEPS) -> dict:
    return {
        "normalization_techniques": len(steps),
        "normalization_steps": [step for step, _undoes, _functions in steps],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true",
                    help="write the measurement into stats/current.json")
    args = ap.parse_args()
    m = measure()

    print(f"normalization techniques: {m['normalization_techniques']}")
    for step, undoes, functions in NORMALIZATION_STEPS:
        print(f"  {step:22s} {', '.join(functions) or '(inline)'}  ·  {undoes}")

    if args.write:
        sp = ROOT / "stats" / "current.json"
        stats = json.loads(sp.read_text())
        stats["normalization_techniques"] = m["normalization_techniques"]
        stats["normalization_stats_generated_by"] = "tools/gen_normalization_stats.py"
        sp.write_text(json.dumps(stats, indent=2) + "\n")
        print(f"\nwrote {sp.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
