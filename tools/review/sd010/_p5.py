"""The cost gate, with the NUMBER exposed.

r1: "Numeric ratio is UNMEASURED: the supplied wrapper does not expose it on
success." Correct -- it ran pytest and pytest prints a dot. This driver
computes the same ratio the gate asserts and prints every row, then applies
the gate itself so the exit code still means something.

The shapes and the gate value are imported FROM THE TEST MODULE, not copied, so
the number printed here cannot drift away from the number enforced in CI.
"""
import copy, os, sys, time
D = sys.argv[1]
HEAD = os.path.join(D, "head")
sys.path.insert(0, HEAD); sys.path.insert(0, os.path.join(HEAD, "tests"))
from sunglasses.patterns import PATTERNS
from sunglasses.engine import SunglassesEngine
import test_sd010_embedded_boundary as T

RULE = "GLS-SD-010-EMB"
ship = SunglassesEngine()
base = SunglassesEngine(patterns=[p for p in copy.deepcopy(PATTERNS) if p["id"] != RULE])

def elapsed(e, text, reps=3):
    best = None
    for _ in range(reps):
        t = time.perf_counter(); e.scan(text, channel="file")
        d = time.perf_counter() - t
        best = d if best is None else min(best, d)
    return best

tw = tn = 0.0
for name, seed in T.PATHOLOGICAL.items():
    text = (seed * ((T.REPEAT_BYTES // len(seed)) + 1))[:T.REPEAT_BYTES]
    a = elapsed(base, text); b = elapsed(ship, text)
    tn += a; tw += b
    print(f"  {name:30} without {a*1000:8.2f}ms  with {b*1000:8.2f}ms  x{b/a:.2f}")
overall = tw / tn if tn else float("inf")
print(f"  OVERALL x{overall:.2f}   gate {T.COST_RATIO}   "
      f"({'PASS' if overall <= T.COST_RATIO else 'FAIL'})")
print(f"  (a RATIO, not seconds: both halves pay for whatever runner this is)")
sys.exit(0 if overall <= T.COST_RATIO else 1)
