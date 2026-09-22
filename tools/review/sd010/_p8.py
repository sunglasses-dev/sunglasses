"""Is the inline (?-i:) scope reachable in EVERY evaluation mode?

Rounds 2 and 3 both left this UNMEASURED, and round 3 refused item 9 partly on
it. The engine compiles each regex into one of four modes (`plain`, `guarded`,
`windowed`, `anchored` -- the engine's own names; a ruling called the last
`anchor_terms`, which is the FIELD that opts into it). Which mode a rule gets
is decided by its SHAPE, so it cannot be selected per scan.

Forcing the real rule into `guarded` would require a caret-led predicate, which
changes what it matches -- that would measure a different rule and report it as
this one. So this builds a MINIMAL SYNTHETIC rule per mode, each carrying the
same `(?-i:...)` construct, and asks whether the scope survives compilation in
that mode. That isolates the question honestly instead of pretending.

THE MODE IS VERIFIED, NEVER ASSUMED: after construction the engine's own
`_compiled_by_id` is read back, and a rule that did not land in the intended
mode is reported as UNMEASURED for that mode rather than scored.
"""
import copy
import os
import sys

D = sys.argv[1]
WANT = sys.argv[2:] or ["plain", "guarded", "windowed", "anchored"]
sys.path.insert(0, os.path.join(D, "head"))
from sunglasses.patterns import PATTERNS
from sunglasses.engine import SunglassesEngine

KEY = "ZZTESTKEY"
# Each shape carries the SAME case-sensitive construct. Only the surrounding
# form differs, and that form is what steers the engine's mode choice.
SHAPES = {
    "plain":    {"regex": [r"(?-i:" + KEY + r")\s*="]},
    "windowed": {"regex": [r"(?=[\s\S]*)(?-i:" + KEY + r")\s*="]},
    "guarded":  {"regex": [r"(?m)^(?!NEVERMATCHXQ)(?=.*(?-i:" + KEY + r"))"
                           r".*(?-i:" + KEY + r")\s*="]},
    # THE ANCHOR TERM IS DECLARED FOLDED, because the engine refuses an
    # unfolded one: "anchor term 'ZZTESTKEY' is not what the fold produces
    # ('zztestkey'), so it would be looked for in a view it cannot appear in".
    # That refusal is also what makes this the mode worth measuring: the
    # PREFILTER finds the term case-INSENSITIVELY and the regex then applies
    # case-SENSITIVELY inside the window, so if (?-i:) were going to be lost
    # anywhere, it would be here.
    "anchored": {"regex": [r"(?-i:" + KEY + r")\s*="],
                 "anchor_terms": [KEY.lower()], "anchor_span": 200},
}

def build(mode):
    rule = {
        "id": f"GLS-MODE-PROBE-{mode.upper()}",
        "name": f"mode probe ({mode})",
        "category": "secret_detection",
        "severity": "high",
        "channel": ["file"],
        "description": "synthetic probe; not a shipped rule",
    }
    rule.update(SHAPES[mode])
    pats = copy.deepcopy(PATTERNS) + [rule]
    return SunglassesEngine(patterns=pats), rule["id"]

rows, bad = [], 0
for mode in WANT:
    if mode not in SHAPES:
        print(f"  {mode:9} *** UNKNOWN MODE, not measured ***")
        bad += 1
        continue
    eng, rid = build(mode)
    got_modes = [m for m, _rx, _x in eng._compiled_by_id.get(rid, ())]
    landed = got_modes[0] if got_modes else "NONE"
    if landed != mode:
        # Do NOT score it. The engine chose a different mode, so whatever this
        # measures is not the mode that was asked for.
        print(f"  {mode:9} intended={mode} landed={landed}  "
              f"*** UNMEASURED: the engine chose another mode ***")
        bad += 1
        continue
    def fires(text):
        d = eng.scan(text, channel="file").to_dict()
        return rid in {f["id"] for f in d["findings"]}
    upper = fires(f"{KEY}=secretvalue")
    lower = fires(f"{KEY.lower()}=secretvalue")
    ok = upper and not lower
    bad += not ok
    rows.append((mode, landed, upper, lower, ok))
    print(f"  mode={mode:9} landed={landed:9} UPPER={'fires' if upper else 'MISS '} "
          f"lower={'FIRES' if lower else 'clean'}  {'OK' if ok else '*SCOPE LOST*'}")

print(f"MODES {len(rows)-sum(1 for r in rows if not r[4])}/{len(rows)} kept the "
      f"case scope" + (f"; {bad} row(s) not measured or failed" if bad else ""))
sys.exit(0 if bad == 0 else 1)
