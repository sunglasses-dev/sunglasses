"""Lab finding B1: super-linear (quadratic) regex cost on a newline run.

Plain words: two rules (GLS-IP-006 and GLS-EX-030) start with an alternation
whose branch `[\\n.!?;:"'\\[{(]\\s*` lets `\\s*` swallow every following newline
and then give them back one at a time when the verb that must follow is not
there. Every newline in the document is a fresh start position, so the total
work is roughly (number of newlines) squared. A 16 KB file that holds the two
words the prefilter needs ("your" and "reply") plus a run of newlines keeps
`scan()` busy for well over 10 s on the `file` channel; 1 MiB (the input cap)
would take hours. The scan is run in a SUBPROCESS with a hard timeout so this
test can never hang CI; it fails on current code and passes once the rule's
cost is bounded (on main since #340 the engine runs these six regexes in a
lead-in mode that finds the start without walking the run).
"""
import json
import os
import subprocess
import sys

import pytest

BUDGET_S = 2.0
N_NEWLINES = 16_000   # ~16 KB, far under the 1 MiB cap

_CHILD = r"""
import json, sys, time
from sunglasses.engine import SunglassesEngine
seed, n, channel = sys.argv[1], int(sys.argv[2]), sys.argv[3]
engine = SunglassesEngine()
text = seed + "\n" * n
t = time.perf_counter()
result = engine.scan(text, channel=channel)
print(json.dumps({"sec": time.perf_counter() - t, "decision": result.decision}))
"""


def _scan_in_subprocess(seed: str, n: int, channel: str, timeout: float):
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD, seed, str(n), channel],
            capture_output=True, text=True, timeout=timeout,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
    except subprocess.TimeoutExpired:
        return None
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("seed,channel,rule", [
    ("your reply ", "file", "GLS-IP-006"),
    ("post ", "web_content", "GLS-EX-030"),
])
def test_newline_run_scan_finishes_within_budget(seed, channel, rule):
    # Engine construction is ~1.5 s on its own, so the child gets BUDGET_S on
    # top of a generous construction allowance. The assertion is on the scan
    # time the child measured, not on the wall clock of the whole process.
    outcome = _scan_in_subprocess(seed, N_NEWLINES, channel, timeout=BUDGET_S + 15)
    assert outcome is not None, (
        f"{rule}: scanning {N_NEWLINES} newlines seeded with {seed!r} on channel "
        f"{channel!r} did not even finish inside {BUDGET_S + 15:.0f} s (killed)")
    assert outcome["sec"] < BUDGET_S, (
        f"{rule}: scan of ~{N_NEWLINES} bytes took {outcome['sec']:.1f} s "
        f"(budget {BUDGET_S} s); cost is quadratic in the newline count")


def test_control_same_bytes_without_the_seed_is_fast():
    # The newline run on its own is cheap: the prefilter skips both rules when
    # the required literals are absent. This pins the DIAGNOSIS, not the bug.
    outcome = _scan_in_subprocess("hello ", N_NEWLINES, "file", timeout=BUDGET_S + 15)
    assert outcome is not None and outcome["sec"] < BUDGET_S
